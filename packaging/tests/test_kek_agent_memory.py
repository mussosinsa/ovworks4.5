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
        config = dict(self.config, watch_path=[str(root)])
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o640)
        return config_path, files

    def _paths_allowed(self):
        return mock.patch.multiple(
            encryptor,
            _within_allowed_root=mock.Mock(return_value=True),
            validate_ovirt_path=mock.Mock(side_effect=lambda p, **k: Path(p).stat()))

    def test_each_file_gets_a_dek_wrapped_by_a_pbkdf2_kek_and_both_are_recorded(self):
        config_path, files = self._install()
        encryptor.load_memory_passphrase(self.socket, bytearray(PASSPHRASE))
        with self._paths_allowed(), mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(0, encrypt_conf_files.main(["--config", str(config_path)]))
        salts = set()
        for path in files:
            data = path.read_bytes()
            magic, _v, iterations, salt, _kn, _dn, wrapped = encryptor.HEADER.unpack_from(data)
            self.assertEqual((b"OVENC001", 600000, 48), (magic, iterations, wrapped))
            salts.add(salt)
            self.assertIn(b"secret-", encryptor.decrypt_gcm_bytes(data, PASSPHRASE))
        self.assertEqual(2, len(salts))     # a KEK of its own per file
        self.assertEqual("OVENC001", json.loads(config_path.read_text())["active_format"])
        events = [(e["event"], e.get("file")) for e in self.events()]
        for path in files:
            self.assertIn(("CRYPTO_KEY_CREATED", path.name), events)
            self.assertIn(("CONFIG_FILE_ENCRYPTION_COMPLETED", path.name), events)
        self.assertNotIn(PASSPHRASE.decode(), json.dumps(self.events()))

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
        files[0].write_bytes(encryptor.encrypt_bytes(b'ENGINE_DB_PASSWORD="pw"\n', PASSPHRASE))
        config_path.chmod(0o640)
        tool = str(ENCRYPTOR_DIR / "encryptor.py")
        with mock.patch.object(configfile, "_ENCRYPTOR_PATH", tool), \
                mock.patch.object(configfile, "_ENCRYPTOR_CONFIG_PATH", str(config_path)), \
                mock.patch.object(configfile, "_load_encryptor_module", lambda: encryptor):
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

    def test_unlock_checks_the_passphrase_against_an_encrypted_file(self):
        config_path, files = self._install()
        files[0].write_bytes(encryptor.encrypt_bytes(b"x=1\n", PASSPHRASE))
        config = json.loads(config_path.read_text())
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
                  "secret_file": str(secret_file)}
        config_path.write_text(json.dumps(config))
        with self._paths_allowed(), mock.patch("sys.stdout", new=io.StringIO()), \
                mock.patch.object(encryptor, "MEMORY_KEK_SOCKET", self.socket):
            moved = kek_agent.migrate(str(config_path), config,
                                      reader=_reader(PASSPHRASE, PASSPHRASE))
        self.assertEqual(files, moved)
        for path in files:
            self.assertIn(b"secret-", encryptor.decrypt_gcm_bytes(path.read_bytes(), PASSPHRASE))
        written = json.loads(config_path.read_text())
        self.assertNotIn("secret_file", written)
        self.assertEqual({"enabled": True, "socket": self.socket}, written["kek_agent"])
        self.assertFalse(secret_file.exists())
        self.assertEqual(bytearray(PASSPHRASE), self.holder.get())


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not usable here")
class KekAgentUnitTest(unittest.TestCase):

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
