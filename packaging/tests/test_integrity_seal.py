import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parents[2]
ENCRYPTOR_DIR = ROOT / "packaging" / "encryptor"
sys.path.insert(0, str(ROOT / "packaging" / "pythonlib"))
sys.path.insert(0, str(ENCRYPTOR_DIR))

import encryptor  # noqa: E402
import integrity_seal  # noqa: E402


class IntegritySealTest(unittest.TestCase):
    """The AIDE baseline and its configuration are sealed under the DEK, and the seal is checked
    before every verification: rewritten to match altered files, they no longer verify."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.config = self.dir / "ovworks-aide.conf"
        self.database = self.dir / "ovworks.db.gz"
        self.seal_path = self.dir / "ovworks.db.seal"
        self.config.write_text("database=file:/var/lib/aide/ovworks.db.gz\n")
        self.database.write_bytes(b"\x1f\x8b baseline")
        self.dek = bytearray(os.urandom(32))
        patcher = mock.patch.object(integrity_seal, "_dek", lambda config: bytearray(self.dek))
        patcher.start()
        self.addCleanup(patcher.stop)

    def seal(self):
        with mock.patch.object(encryptor, "_atomic_write",
                               lambda path, data, owner=None, mode=0o600: Path(path).write_bytes(data)):
            integrity_seal.seal(aide_config=self.config, database=self.database, seal_path=self.seal_path)

    def verify(self):
        out = io.StringIO()
        rc = integrity_seal.verify(aide_config=self.config, database=self.database,
                                   seal_path=self.seal_path, out=out)
        return rc, out.getvalue()

    def test_a_sealed_baseline_verifies(self):
        self.seal()
        record = json.loads(self.seal_path.read_text())
        self.assertEqual(1, record["version"])
        self.assertEqual(encryptor.dek_id(self.dek).hex(), record["dek_id"])
        self.assertNotIn(self.dek.hex(), self.seal_path.read_text())
        rc, out = self.verify()
        self.assertEqual(0, rc, out)

    def test_a_rewritten_database_or_configuration_is_reported_as_aide_reports_a_change(self):
        self.seal()
        self.database.write_bytes(b"\x1f\x8b rewritten to match altered files")
        rc, out = self.verify()
        self.assertEqual(integrity_seal.EXIT_TAMPERED, rc)
        self.assertIn("changed: %s" % self.database, out)
        self.config.write_text("# nothing measured\n")
        rc, out = self.verify()
        self.assertIn("changed: %s" % self.config, out)
        self.database.unlink()
        rc, out = self.verify()
        self.assertIn("removed: %s" % self.database, out)

    def test_a_seal_written_without_the_dek_does_not_verify(self):
        self.seal()
        record = json.loads(self.seal_path.read_text())
        self.database.write_bytes(b"altered")
        # Recomputed with a key that is not the DEK's.
        record["database"] = integrity_seal.file_mac(b"\0" * 32, "database", self.database)
        self.seal_path.write_text(json.dumps(record))
        rc, out = self.verify()
        self.assertEqual(integrity_seal.EXIT_TAMPERED, rc)

    def test_what_cannot_be_checked_is_said_and_not_passed(self):
        rc, _ = self.verify()   # never sealed
        self.assertEqual(integrity_seal.EXIT_UNVERIFIABLE, rc)
        self.seal()
        self.dek = bytearray(os.urandom(32))   # another DEK
        rc, _ = self.verify()
        self.assertEqual(integrity_seal.EXIT_UNVERIFIABLE, rc)

    def _open(self, tmp_db, tmp_config):
        out = io.StringIO()
        with mock.patch.object(encryptor, "_atomic_write",
                               lambda path, data, owner=None, mode=0o600: Path(path).write_bytes(data)):
            rc = integrity_seal.open_baseline(
                aide_config=self.config, database=self.database, seal_path=self.seal_path,
                tmp_database=tmp_db, tmp_config=tmp_config, out=out)
        return rc, out.getvalue()

    def test_the_sealed_baseline_is_encrypted_at_rest(self):
        self.seal()
        self.assertTrue(self.database.read_bytes().startswith(encryptor.ENVELOPE_MAGIC))

    def test_open_decrypts_the_baseline_and_writes_a_config_for_aide(self):
        self.seal()
        tmp_db = self.dir / "open.db.gz"
        tmp_config = self.dir / "open.conf"
        rc, out = self._open(tmp_db, tmp_config)
        self.assertEqual(0, rc, out)
        # The original plaintext baseline (setUp) comes back; AIDE reads it through tmp_config.
        self.assertEqual(b"\x1f\x8b baseline", tmp_db.read_bytes())
        self.assertIn("database_in=file:%s" % tmp_db, tmp_config.read_text())
        integrity_seal.close_baseline(tmp_db, tmp_config)
        self.assertFalse(tmp_db.exists())
        self.assertFalse(tmp_config.exists())

    def test_the_open_config_names_the_baseline_for_the_installed_aide(self):
        self.assertEqual("database", integrity_seal.installed_aide_database_key(run=lambda: "Aide 0.16"))
        self.assertEqual("database_in", integrity_seal.installed_aide_database_key(run=lambda: "Aide 0.19.2"))
        out = self.dir / "open.conf"
        integrity_seal.write_open_config(self.config, "/dev/shm/x.db.gz", out, database_key="database")
        self.assertIn("database=file:/dev/shm/x.db.gz", out.read_text())

    def test_open_reports_a_tampered_baseline_and_leaves_no_plaintext(self):
        self.seal()
        self.database.write_bytes(b"\x1f\x8b rewritten to match altered files")
        tmp_db = self.dir / "open.db.gz"
        tmp_config = self.dir / "open.conf"
        rc, _ = self._open(tmp_db, tmp_config)
        self.assertEqual(integrity_seal.EXIT_TAMPERED, rc)
        self.assertFalse(tmp_db.exists())
        self.assertFalse(tmp_config.exists())

    def test_it_takes_no_path_from_its_caller(self):
        parser_source = (ENCRYPTOR_DIR / "integrity_seal.py").read_text()
        main = parser_source[parser_source.index("def main("):]
        self.assertNotIn("add_argument(\"--config", main)
        self.assertEqual(["--seal", "--verify"],
                         [a for a in ("--seal", "--verify") if 'add_argument("%s"' % a in main])


if __name__ == "__main__":
    unittest.main()
