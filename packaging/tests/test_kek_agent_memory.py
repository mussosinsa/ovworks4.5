import io
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parents[2]
ENCRYPTOR_DIR = ROOT / "packaging" / "encryptor"
sys.path.insert(0, str(ROOT / "packaging" / "pythonlib"))
sys.path.insert(0, str(ENCRYPTOR_DIR))

from ovirt_engine import cryptoevents  # noqa: E402

try:
    import encryptor  # noqa: E402
    import encrypt_conf_files  # noqa: E402
    import kek_agent  # noqa: E402
    CRYPTOGRAPHY_AVAILABLE = True
except (ModuleNotFoundError, BaseException) as error:  # a broken binding panics, not raises
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        raise
    CRYPTOGRAPHY_AVAILABLE = False

PASSPHRASE = b"ab12cd"


def _reader(*answers):
    answers = list(answers)
    typed = []

    def read(prompt):
        value = bytearray(answers.pop(0))
        typed.append(value)
        return value
    read.typed = typed
    return read


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not usable here")
class KekAgentMemoryTest(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.spool = self.dir / "spool"
        patcher = mock.patch.object(cryptoevents, "SPOOL_DIR", str(self.spool))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.socket = str(self.dir / "agent.sock")
        patcher = mock.patch.object(encryptor, "MEMORY_KEK_SOCKET_ROOT", str(self.dir))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.holder = kek_agent.Holder()
        self.stop = threading.Event()
        ready = threading.Event()
        with mock.patch.object(kek_agent, "_harden"):
            thread = threading.Thread(
                target=kek_agent.serve,
                args=(self.socket, self.holder, ready, self.stop), daemon=True)
            thread.start()
        ready.wait(5)
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.stop.set)
        self.config = {"kek_agent": {"enabled": True, "socket": self.socket}}

    def events(self):
        if not self.spool.is_dir():
            return []
        paths = sorted(self.spool.glob("*.json"), key=lambda p: p.stat().st_mtime_ns)
        return [json.loads(p.read_text()) for p in paths]

    # -- passphrase rule ------------------------------------------------------------------

    def test_the_passphrase_needs_six_characters_or_more(self):
        for refused in (b"", b"abc", b"abcde", "가나다라마".encode("utf-8"), b"ab\x01def",
                        b"a" * 257):
            with self.assertRaises(encryptor.EncryptorError, msg=refused):
                encryptor.check_memory_passphrase(bytearray(refused))
        for accepted in (b"abcdef", "가나다라마바".encode("utf-8"), b"a" * 256):
            encryptor.check_memory_passphrase(bytearray(accepted))
        self.assertEqual(
            cryptoevents.REASON_PASSPHRASE_REJECTED,
            cryptoevents.reason_for(self._error(encryptor.check_memory_passphrase, b"abcde")))

    @staticmethod
    def _error(call, *args):
        try:
            call(*args)
        except encryptor.EncryptorError as error:
            return error
        raise AssertionError("no error")

    # -- the agent ------------------------------------------------------------------------

    def test_the_agent_holds_the_passphrase_in_memory_and_forgets_it(self):
        self.assertFalse(encryptor.memory_passphrase_loaded(self.socket))
        encryptor.load_memory_passphrase(self.socket, bytearray(PASSPHRASE))
        self.assertTrue(encryptor.memory_passphrase_loaded(self.socket))
        fetched = encryptor.fetch_memory_passphrase(self.socket)
        self.assertEqual(bytearray(PASSPHRASE), fetched)
        self.assertIsInstance(fetched, bytearray)
        held = self.holder.get()
        encryptor.kek_agent_request(self.socket, "clear")
        self.assertEqual(bytearray(len(PASSPHRASE)), held)    # overwritten, not just dropped
        with self.assertRaisesRegex(encryptor.EncryptorError, "not loaded in memory"):
            encryptor.fetch_memory_passphrase(self.socket)

    def test_only_root_loads_and_only_root_or_the_engine_reads(self):
        holder = kek_agent.Holder()
        holder.load(bytearray(PASSPHRASE))

        def ask(uid, op, payload=None):
            server, client = socket.socketpair()
            with server, client:
                encryptor.agent_send(client, {"op": op}, payload)
                result = kek_agent.handle(server, holder, uid, own_uid=990)
                return result, encryptor.agent_receive(client)

        self.assertEqual("denied", ask(1234, "get")[0])
        self.assertEqual("denied", ask(1234, "status")[0])
        self.assertEqual("denied", ask(990, "load", bytearray(b"wxyz"))[0])
        self.assertEqual("denied", ask(990, "clear")[0])
        result, (_header, payload) = ask(990, "get")
        self.assertEqual(("ok", bytearray(PASSPHRASE)), (result, payload))
        self.assertEqual("invalid", ask(0, "load", bytearray(b"abc"))[0])
        self.assertEqual(bytearray(PASSPHRASE), holder.get())

    def test_the_passphrase_goes_only_to_a_trusted_agent(self):
        with mock.patch.object(encryptor, "_trusted_agent_uids", return_value=set()):
            with self.assertRaisesRegex(encryptor.EncryptorError, "untrusted"):
                encryptor.load_memory_passphrase(self.socket, bytearray(PASSPHRASE))
        self.assertFalse(self.holder.loaded)

    def test_no_file_or_environment_stands_in_for_the_passphrase_in_memory(self):
        secret_file = self.dir / "passphrase"
        secret_file.write_bytes(b"from-a-file")
        secret_file.chmod(0o600)
        config = dict(self.config, secret_file=str(secret_file))
        with mock.patch.dict(os.environ, {encryptor.PASSPHRASE_ENV: "from-env"}):
            error = self._error(encryptor.obtain_passphrase, config)
        self.assertEqual(cryptoevents.REASON_PASSPHRASE_UNAVAILABLE,
                         cryptoevents.reason_for(error))
        encryptor.load_memory_passphrase(self.socket, bytearray(PASSPHRASE))
        self.assertEqual(bytearray(PASSPHRASE), encryptor.obtain_passphrase(config))

    # -- envelope encryption --------------------------------------------------------------

    def _install(self, names=("10-setup-database.conf", "internal.properties")):
        root = self.dir / "etc"
        (root / "engine.conf.d").mkdir(parents=True, exist_ok=True)
        files = []
        for name in names:
            path = root / "engine.conf.d" / name
            path.write_bytes(b'ENGINE_DB_PASSWORD="secret-%s"\n' % name.encode())
            path.chmod(0o640)
            files.append(path)
        config_path = self.dir / "config.json"
        self.dek_file = self.dir / "encryptor" / "dek.enc"
        self.dek_file.parent.mkdir(exist_ok=True)
        config = dict(self.config, watch_path=[str(root)], dek_file=str(self.dek_file))
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o640)
        return config_path, files

    def _paths_allowed(self):
        return mock.patch.multiple(
            encryptor,
            _within_allowed_root=mock.Mock(return_value=True),
            validate_ovirt_path=mock.Mock(side_effect=lambda p, **k: Path(p).stat()))

    def test_one_dek_per_installation_wrapped_by_the_pbkdf2_kek_and_recorded(self):
        config_path, files = self._install()
        encryptor.load_memory_passphrase(self.socket, bytearray(PASSPHRASE))
        with self._paths_allowed(), mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(0, encrypt_conf_files.main(["--config", str(config_path)]))
        # The DEK file: AES-256-GCM under PBKDF2-HMAC-SHA256(passphrase, 256-bit salt, 600000).
        data = self.dek_file.read_bytes()
        magic, _v, iterations, salt, nonce, wrapped = encryptor.DEK_HEADER.unpack_from(data)
        self.assertEqual((b"OVDEK001", 600000, 32, 48), (magic, iterations, len(salt), wrapped))
        self.assertEqual(0o640, self.dek_file.stat().st_mode & 0o777)
        with self._paths_allowed():
            dek = encryptor.unwrap_dek(data, PASSPHRASE)
            with self.assertRaisesRegex(encryptor.EncryptorError, "Authentication failed"):
                encryptor.unwrap_dek(data, b"wrong!")
        self.assertEqual(32, len(dek))
        # Every file under that one DEK; no key material in the files themselves.
        for path in files:
            content = path.read_bytes()
            magic, _v, key_id, _nonce = encryptor.ENVELOPE_HEADER.unpack_from(content)
            self.assertEqual((b"OVENC002", encryptor.dek_id(dek)), (magic, key_id))
            self.assertIn(b"secret-", encryptor.decrypt_envelope(content, dek))
        written = json.loads(config_path.read_text())
        self.assertEqual(("OVENC002", str(self.dek_file)),
                         (written["active_format"], written["dek_file"]))
        events = [(e["event"], e.get("file"), e.get("scheme")) for e in self.events()]
        self.assertEqual(1, events.count(("CRYPTO_KEY_CREATED", "dek.enc", "OVDEK001")))
        for path in files:
            self.assertIn(("CONFIG_FILE_ENCRYPTION_COMPLETED", path.name, "OVENC002"), events)
        self.assertNotIn(PASSPHRASE.decode(), json.dumps(self.events()))
        # A second run reuses the DEK rather than making another.
        files[0].write_bytes(b'ENGINE_DB_PASSWORD="again"\n')
        with self._paths_allowed(), mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(0, encrypt_conf_files.main(["--config", str(config_path)]))
        self.assertEqual(data, self.dek_file.read_bytes())

    def test_no_dek_is_made_without_the_approved_generator_and_that_is_recorded(self):
        config_path, files = self._install()
        encryptor.load_memory_passphrase(self.socket, bytearray(PASSPHRASE))
        with self._paths_allowed(), mock.patch("sys.stderr", new=io.StringIO()), \
                mock.patch.object(encryptor, "_csprng", None):
            self.assertEqual(1, encrypt_conf_files.main(["--config", str(config_path)]))
        self.assertFalse(self.dek_file.exists())
        self.assertFalse(encryptor.is_encrypted(files[0]))
        self.assertEqual([("CRYPTO_KEY_CREATION_FAILED", "dek.enc", "RNG_UNAVAILABLE")],
                         [(e["event"], e.get("file"), e.get("reason")) for e in self.events()])

    def test_a_missing_or_foreign_dek_is_reported_as_such(self):
        config_path, files = self._install(("10-setup-database.conf",))
        config = json.loads(config_path.read_text())
        with self._paths_allowed():
            dek, created = encryptor.ensure_dek(config, PASSPHRASE)
            self.assertTrue(created)
            envelope = encryptor.encrypt_envelope(b"x=1\n", dek)
            other = encryptor.encrypt_envelope(b"x=1\n", bytearray(32))
            with self.assertRaisesRegex(encryptor.EncryptorError, "another DEK"):
                encryptor.decrypt_bytes(other, PASSPHRASE, config)
            self.assertEqual(b"x=1\n", encryptor.decrypt_bytes(envelope, PASSPHRASE, config))
            self.dek_file.unlink()
            error = self._error(encryptor.decrypt_bytes, envelope, PASSPHRASE, config)
        self.assertEqual(cryptoevents.REASON_DEK_UNAVAILABLE, cryptoevents.reason_for(error))

    def test_encrypting_without_the_passphrase_in_memory_is_recorded_as_a_failure(self):
        config_path, files = self._install()
        with self._paths_allowed(), mock.patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(1, encrypt_conf_files.main(["--config", str(config_path)]))
        self.assertEqual([("CRYPTO_KEY_CREATION_FAILED", "PASSPHRASE_UNAVAILABLE")],
                         [(e["event"], e["reason"]) for e in self.events()])
        self.assertFalse(encryptor.is_encrypted(files[0]))

    def test_the_engine_start_decrypts_with_the_passphrase_in_memory_and_records_it(self):
        from ovirt_engine import configfile
        config_path, files = self._install(("10-setup-database.conf",))
        with self._paths_allowed():
            dek, _created = encryptor.ensure_dek(json.loads(config_path.read_text()), PASSPHRASE)
        files[0].write_bytes(encryptor.encrypt_envelope(b'ENGINE_DB_PASSWORD="pw"\n', dek))
        config_path.chmod(0o640)
        self.dek_file.unlink()   # the event of creating it is not this test's
        self.dek_file.write_bytes(encryptor.wrap_dek(dek, PASSPHRASE))
        self.dek_file.chmod(0o640)
        for entry in self.spool.glob("*.json"):
            entry.unlink()
        tool = str(ENCRYPTOR_DIR / "encryptor.py")
        with mock.patch.object(configfile, "_ENCRYPTOR_PATH", tool), \
                mock.patch.object(configfile, "_ENCRYPTOR_CONFIG_PATH", str(config_path)), \
                mock.patch.object(configfile, "_load_encryptor_module", lambda: encryptor), \
                mock.patch.object(encryptor, "_within_allowed_root", return_value=True):
            loader = configfile.ConfigFile(cryptoEventSource="engine-start")
            with self.assertRaisesRegex(Exception, "not loaded in memory"):
                loader._loadFileContent(str(files[0]))
            encryptor.load_memory_passphrase(self.socket, bytearray(PASSPHRASE))
            self.assertIn('ENGINE_DB_PASSWORD="pw"', loader._loadFileContent(str(files[0])))
        self.assertEqual(
            [("CONFIG_FILE_DECRYPTION_FAILED", "PASSPHRASE_UNAVAILABLE"),
             ("CONFIG_FILE_DECRYPTION_COMPLETED", None)],
            [(e["event"], e.get("reason")) for e in self.events()])

    # -- unlock after a reboot ------------------------------------------------------------

    def test_unlock_checks_the_passphrase_against_the_dek_file(self):
        config_path, files = self._install()
        config = json.loads(config_path.read_text())
        with self._paths_allowed():
            dek, _created = encryptor.ensure_dek(config, PASSPHRASE)
        files[0].write_bytes(encryptor.encrypt_envelope(b"x=1\n", dek))
        for entry in self.spool.glob("*.json"):
            entry.unlink()
        with self._paths_allowed(), mock.patch("sys.stdout", new=io.StringIO()):
            with self.assertRaisesRegex(encryptor.EncryptorError, "Authentication failed"):
                kek_agent.unlock(config, reader=_reader(b"wrong!"))
            self.assertFalse(self.holder.loaded)
            reader = _reader(PASSPHRASE)
            kek_agent.unlock(config, reader=reader)
        self.assertEqual(bytearray(PASSPHRASE), self.holder.get())
        self.assertEqual(bytearray(len(PASSPHRASE)), reader.typed[0])    # wiped after use
        self.assertEqual(
            [("CRYPTO_KEY_CREATION_FAILED", "AUTHENTICATION_FAILED"), ("CRYPTO_KEY_CREATED", None)],
            [(e["event"], e.get("reason")) for e in self.events()])

    def test_unlock_with_nothing_encrypted_yet_asks_twice(self):
        config_path, _files = self._install()
        config = json.loads(config_path.read_text())
        with self._paths_allowed(), mock.patch("sys.stdout", new=io.StringIO()):
            with self.assertRaisesRegex(encryptor.EncryptorError, "differ"):
                kek_agent.unlock(config, reader=_reader(PASSPHRASE, b"ab13cd"))
        self.assertEqual([("CRYPTO_KEY_CREATION_FAILED", "PASSPHRASE_REJECTED")],
                         [(e["event"], e.get("reason")) for e in self.events()])

    # -- moving an installation off a passphrase file ---------------------------------------

    def test_migrate_moves_files_to_the_memory_passphrase_and_removes_the_file(self):
        config_path, files = self._install()
        secret_file = self.dir / "passphrase"
        secret_file.write_bytes(b"old-random-passphrase\n")
        secret_file.chmod(0o600)
        for path in files:
            path.write_bytes(encryptor.encrypt_bytes(path.read_bytes(), b"old-random-passphrase"))
        config = {"watch_path": json.loads(config_path.read_text())["watch_path"],
                  "secret_file": str(secret_file), "dek_file": str(self.dek_file)}
        config_path.write_text(json.dumps(config))
        with self._paths_allowed(), mock.patch("sys.stdout", new=io.StringIO()), \
                mock.patch.object(encryptor, "MEMORY_KEK_SOCKET", self.socket):
            moved = kek_agent.migrate(str(config_path), config,
                                      reader=_reader(PASSPHRASE, PASSPHRASE))
        self.assertEqual(files, moved)
        with self._paths_allowed():
            dek = encryptor.read_dek({"dek_file": str(self.dek_file)}, PASSPHRASE)
        for path in files:
            self.assertIn(b"secret-", encryptor.decrypt_envelope(path.read_bytes(), dek))
        written = json.loads(config_path.read_text())
        self.assertEqual("OVENC002", written["active_format"])
        self.assertNotIn("secret_file", written)
        self.assertEqual({"enabled": True, "socket": self.socket}, written["kek_agent"])
        self.assertFalse(secret_file.exists())
        self.assertEqual(bytearray(PASSPHRASE), self.holder.get())


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not usable here")
class KekAgentUnitTest(unittest.TestCase):

    def test_the_agent_tells_systemd_once_its_socket_exists(self):
        directory = tempfile.mkdtemp()
        notify_path = os.path.join(directory, "notify")
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify:
            notify.bind(notify_path)
            notify.settimeout(5)
            with mock.patch.dict(os.environ, {"NOTIFY_SOCKET": notify_path}):
                kek_agent._notify_ready()
            self.assertEqual(b"READY=1", notify.recv(64))
        unit = (ROOT / "packaging/services/ovirt-engine/ovirt-engine-kek-agent.service.in") \
            .read_text()
        self.assertIn("Type=notify", unit)

    def test_the_unit_keeps_the_process_off_disk(self):
        unit = (ROOT / "packaging/services/ovirt-engine/ovirt-engine-kek-agent.service.in") \
            .read_text()
        for line in ("LimitCORE=0", "MemorySwapMax=0", "RuntimeDirectoryMode=0700",
                     "User=@ENGINE_USER@", "kek_agent.py --serve"):
            self.assertIn(line, unit)
        engine = (ROOT / "packaging/services/ovirt-engine/ovirt-engine.systemd.in").read_text()
        self.assertIn("Wants=ovirt-engine-kek-agent.service", engine)

    def test_the_header_and_payload_frame(self):
        left, right = socket.socketpair()
        with left, right:
            encryptor.agent_send(left, {"op": "load"}, bytearray(b"abcd"))
            header, payload = encryptor.agent_receive(right)
        self.assertEqual(("load", 4, bytearray(b"abcd")), (header["op"], header["length"], payload))
        self.assertEqual(struct.calcsize("3i"), 12)


if __name__ == "__main__":
    unittest.main()
