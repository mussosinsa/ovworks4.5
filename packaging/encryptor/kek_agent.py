#!/usr/bin/python3
"""Hold the KEK passphrase in memory only, for the engine's configuration-file encryption.

Without Vault the database configuration files are OVENC001 envelopes: each file has a random
data-encryption key (DEK), wrapped by a key-encryption key (KEK) that PBKDF2-HMAC-SHA256 derives
from a passphrase and a salt of the file's own. The passphrase is typed in at engine-setup (or
with --unlock after a reboot) and from then on lives only in this process's memory: never in a
file, the environment, an answer file or a log. Stopping this service, or a reboot, forgets it.

  --serve     run the holder (ovirt-engine-kek-agent.service)
  --unlock    type the passphrase in again after a reboot; checked against an encrypted file
  --lock      forget it now
  --status    whether it is held
  --migrate   move an installation from a passphrase file or Vault to a passphrase in memory
"""

import argparse
import ctypes
import os
import signal
import socket
import stat
import sys
from pathlib import Path

import encryptor

try:
    from ovirt_engine import cryptoevents
except ImportError:  # pragma: no cover - the engine's python library is not installed
    cryptoevents = None

_EVENT_SOURCE = "kek-agent"
_SCHEME = encryptor.MAGIC.decode("ascii")
_PR_SET_DUMPABLE = 4


def _record(event, error=None, **fields):
    """Leaves the result where the engine can report it in the audit log. Never raises."""
    if cryptoevents is None:
        return
    if error is not None:
        fields["reason"] = cryptoevents.reason_for(error)
    cryptoevents.record(getattr(cryptoevents, event), _EVENT_SOURCE, **fields)


def _libc():
    try:
        return ctypes.CDLL(None, use_errno=True)
    except OSError:  # pragma: no cover
        return None


def _harden():
    """No core dump and no ptrace by the same account: the passphrase must not leave memory."""
    libc = _libc()
    if libc is not None and libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        print("kek_agent: could not mark the process non-dumpable", file=sys.stderr)


def _lock_pages(buffer, lock=True):
    """Keeps the passphrase's pages out of swap, where the system allows it. Best effort."""
    libc = _libc()
    if libc is None or not buffer:
        return
    address = ctypes.addressof((ctypes.c_char * len(buffer)).from_buffer(buffer))
    call = libc.mlock if lock else libc.munlock
    call(ctypes.c_void_p(address), ctypes.c_size_t(len(buffer)))


class Holder(object):
    """The one secret this process exists for."""

    def __init__(self):
        self._secret = None

    @property
    def loaded(self):
        return self._secret is not None

    def load(self, secret):
        self.clear()
        _lock_pages(secret)
        self._secret = secret

    def get(self):
        return self._secret

    def clear(self):
        if self._secret is not None:
            encryptor.wipe(self._secret)
            _lock_pages(self._secret, lock=False)
            self._secret = None


def handle(conn, holder, uid, own_uid=None):
    """Answers one request. Root may load and clear; root and the engine's account may read."""
    own_uid = os.geteuid() if own_uid is None else own_uid
    header, payload = encryptor.agent_receive(conn)
    op = header.get("op")
    try:
        if uid not in (0, own_uid):
            encryptor.agent_send(conn, {"ok": False, "error": "denied"})
            return "denied"
        if op == "status":
            encryptor.agent_send(conn, {"ok": True, "loaded": holder.loaded})
        elif op == "get":
            if not holder.loaded:
                encryptor.agent_send(conn, {"ok": False, "error": "not-loaded"})
                return "not-loaded"
            encryptor.agent_send(conn, {"ok": True}, holder.get())
        elif op == "load":
            if uid != 0:
                encryptor.agent_send(conn, {"ok": False, "error": "denied"})
                return "denied"
            if payload is None:
                encryptor.agent_send(conn, {"ok": False, "error": "invalid"})
                return "invalid"
            try:
                encryptor.check_memory_passphrase(payload)
            except encryptor.EncryptorError:
                encryptor.agent_send(conn, {"ok": False, "error": "invalid"})
                return "invalid"
            holder.load(payload)
            payload = None   # held now; not wiped below
            encryptor.agent_send(conn, {"ok": True, "loaded": True})
        elif op == "clear":
            if uid != 0:
                encryptor.agent_send(conn, {"ok": False, "error": "denied"})
                return "denied"
            holder.clear()
            encryptor.agent_send(conn, {"ok": True, "loaded": False})
        else:
            encryptor.agent_send(conn, {"ok": False, "error": "invalid"})
            return "invalid"
        return "ok"
    finally:
        if payload is not None:
            encryptor.wipe(payload)


def serve(socket_path, holder=None, ready=None, stop=None):
    """Runs until SIGTERM. The secret is wiped on the way out."""
    holder = holder or Holder()
    _harden()
    path = Path(socket_path)
    if path.is_socket() or path.is_symlink():
        path.unlink()
    previous = os.umask(0o177)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
    finally:
        os.umask(previous)
    os.chmod(str(path), 0o600)
    server.listen(8)
    server.settimeout(1)

    def _terminate(signum, frame):
        raise SystemExit(0)

    if stop is None:
        signal.signal(signal.SIGTERM, _terminate)
    if ready is not None:
        ready.set()
    try:
        while stop is None or not stop.is_set():
            try:
                conn, _address = server.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(5)
                try:
                    uid = encryptor._peer_uid(conn)
                    result = handle(conn, holder, uid)
                    # The journal keeps who asked for what, never the secret.
                    print("kek_agent: uid=%d result=%s" % (uid, result), flush=True)
                except (OSError, encryptor.EncryptorError) as error:
                    print("kek_agent: request failed: %s" % error, file=sys.stderr, flush=True)
    finally:
        holder.clear()
        server.close()
        try:
            path.unlink()
        except OSError:
            pass


def _encrypted_targets(config, magics=(encryptor.MAGIC, encryptor.VAULT_MAGIC)):
    """The protected configuration files, as encrypt_conf_files.py finds them."""
    names = set(config.get("allowed_files", sorted(encryptor.ALLOWED_CONFIG_BASENAMES)))
    if not names <= encryptor.ALLOWED_CONFIG_BASENAMES:
        raise encryptor.EncryptorError("allowed_files contains an unapproved filename")
    targets = []
    for root in config.get("watch_path", [str(path) for path in encryptor.ALLOWED_ROOTS]):
        root = Path(root)
        if not encryptor._within_allowed_root(root) or root.is_symlink() or not root.is_dir():
            continue
        for directory, directories, files in os.walk(str(root), followlinks=False):
            directories[:] = [d for d in directories if not (Path(directory) / d).is_symlink()]
            for name in sorted(files):
                path = Path(directory) / name
                if name in names and not path.is_symlink() and path.is_file():
                    with path.open("rb") as stream:
                        if stream.read(len(encryptor.MAGIC)) in magics:
                            targets.append(path)
    return targets


def verify_passphrase(config, passphrase):
    """Opens one OVENC001 file with it: the AES-GCM tag proves it is the passphrase in use.

    @return the file it was checked against, or None when nothing is encrypted yet
    """
    for path in _encrypted_targets(config, magics=(encryptor.MAGIC,)):
        encryptor.decrypt_gcm_bytes(path.read_bytes(), passphrase)
        return path
    return None


def _socket_of(config):
    settings = encryptor.memory_kek_settings(config)
    if settings is None:
        raise encryptor.EncryptorError(
            "kek_agent is not enabled in the encryptor configuration")
    return settings["socket"]


def _require_root():
    if os.geteuid() != 0:
        raise encryptor.EncryptorError("This must run as root")


def unlock(config, reader=encryptor.read_secret):
    """Types the passphrase in again, after the agent lost it (a reboot, a restart)."""
    _require_root()
    socket_path = _socket_of(config)
    passphrase = again = None
    try:
        passphrase = reader("KEK passphrase: ")
        encryptor.check_memory_passphrase(passphrase)
        checked = verify_passphrase(config, passphrase)
        if checked is None:
            # Nothing to check it against: a typing mistake would become the passphrase.
            again = reader("KEK passphrase again: ")
            if passphrase != again:
                raise encryptor.EncryptorError("The two passphrases differ")
        encryptor.load_memory_passphrase(socket_path, passphrase)
    except Exception as error:
        _record("KEY_CREATION_FAILED", error, scheme=_SCHEME)
        raise
    finally:
        encryptor.wipe(passphrase)
        encryptor.wipe(again)
    _record("KEY_CREATED", scheme=_SCHEME)
    print("KEK passphrase loaded into memory%s" % (
        "" if checked is None else " (checked against %s)" % checked.name))


def migrate(config_path, config, reader=encryptor.read_secret):
    """Re-encrypts every protected file under a passphrase typed in here, held in memory.

    From a passphrase file (OVENC001) or Vault Transit (OVVLT001). Everything is decrypted,
    re-encrypted and verified in memory before anything is written, and a file already under
    the new passphrase is left as it is, so a run that stopped half way is finished by running
    it again. The old passphrase file is overwritten and removed at the end.
    """
    _require_root()
    if encryptor.memory_kek_settings(config) is not None:
        raise encryptor.EncryptorError("The KEK passphrase is already held in memory")
    socket_path = config.get("kek_agent", {}).get("socket", encryptor.MEMORY_KEK_SOCKET) \
        if isinstance(config.get("kek_agent"), dict) else encryptor.MEMORY_KEK_SOCKET
    transit_client = encryptor.vault_client_from_config(config)
    targets = _encrypted_targets(config)
    old_passphrase = None
    if any(path.read_bytes()[:8] == encryptor.MAGIC for path in targets):
        old_passphrase = encryptor.obtain_passphrase(config, transit_client=transit_client)
    passphrase = again = None
    try:
        passphrase = reader("New KEK passphrase (%d+ characters): "
                            % encryptor.MEMORY_MIN_PASSPHRASE)
        again = reader("New KEK passphrase again: ")
        try:
            encryptor.check_memory_passphrase(passphrase)
            if passphrase != again:
                raise encryptor.EncryptorError("The two passphrases differ")
        except encryptor.EncryptorError as error:
            _record("KEY_CREATION_FAILED", error, scheme=_SCHEME)
            raise
        pending = []
        for path in targets:
            data = path.read_bytes()
            try:
                plaintext = encryptor.decrypt_bytes(
                    data, old_passphrase, config, deny_legacy_cbc=True,
                    transit_client=transit_client)
            except encryptor.EncryptorError:
                if data.startswith(encryptor.MAGIC):
                    encryptor.decrypt_gcm_bytes(data, passphrase)   # already moved, or raises
                    continue
                raise
            try:
                moved = encryptor.encrypt_bytes(plaintext, passphrase)
                if encryptor.decrypt_gcm_bytes(moved, passphrase) != plaintext:
                    raise encryptor.EncryptorError("Post-encryption self-verification failed")
            except encryptor.EncryptorError as error:
                _record("ENCRYPTION_FAILED", error, file=path.name, scheme=_SCHEME)
                raise
            pending.append((path, moved))
        try:
            encryptor.load_memory_passphrase(socket_path, passphrase)
        except encryptor.EncryptorError as error:
            _record("KEY_CREATION_FAILED", error, scheme=_SCHEME)
            raise
        _record("KEY_CREATED", scheme=_SCHEME)
        for path, moved in pending:
            info = path.stat()
            encryptor._atomic_write(path, moved, owner=(info.st_uid, info.st_gid),
                                    mode=stat.S_IMODE(info.st_mode))
            _record("KEY_CREATED", file=path.name, scheme=_SCHEME)
            _record("ENCRYPTION_COMPLETED", file=path.name, scheme=_SCHEME)
    finally:
        encryptor.wipe(passphrase)
        encryptor.wipe(again)
        if isinstance(old_passphrase, bytearray):
            encryptor.wipe(old_passphrase)
    secret_file = config.pop("secret_file", None)
    if isinstance(config.get("vault_transit"), dict):
        config["vault_transit"]["enabled"] = False
    config["kek_agent"] = {"enabled": True, "socket": socket_path}
    config["active_format"] = _SCHEME
    config["encrypt_flag"] = "YES"
    encryptor.atomic_update_config(config_path, config)
    if secret_file:
        _destroy(Path(secret_file))
    print("Moved %d file(s) to a KEK passphrase held in memory" % len(pending))
    return [path for path, _moved in pending]


def _destroy(path):
    """Overwrites the old passphrase file before removing it. Best effort on journaling FS."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISREG(info.st_mode):
        with path.open("r+b", buffering=0) as stream:
            stream.write(b"\0" * info.st_size)
            os.fsync(stream.fileno())
    path.unlink()
    print("Removed the old passphrase file %s" % path)


def _parser():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--serve", action="store_true")
    action.add_argument("--unlock", action="store_true")
    action.add_argument("--lock", action="store_true")
    action.add_argument("--status", action="store_true")
    action.add_argument("--migrate", action="store_true")
    parser.add_argument("--config", default=str(encryptor.DEFAULT_CONFIG))
    parser.add_argument("--socket", help="for --serve; default %s" % encryptor.MEMORY_KEK_SOCKET)
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        if args.serve:
            serve(args.socket or encryptor.MEMORY_KEK_SOCKET)
            return 0
        config = encryptor._load_crypto_config(args.config)
        if args.migrate:
            migrate(args.config, config)
        elif args.unlock:
            unlock(config)
        elif args.lock:
            _require_root()
            encryptor.kek_agent_request(_socket_of(config), "clear")
            print("KEK passphrase removed from memory")
        else:
            loaded = encryptor.memory_passphrase_loaded(_socket_of(config))
            print("KEK passphrase %s" % ("is held in memory" if loaded else "is NOT loaded"))
            return 0 if loaded else 3
    except (encryptor.EncryptorError, OSError) as error:
        print("kek_agent: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
