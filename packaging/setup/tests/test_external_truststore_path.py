import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
PLUGIN = (
    ROOT
    / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/network'
    / 'ovirtproviderovn.py'
)


class ExternalTruststorePathTest(unittest.TestCase):
    def test_provider_import_recovers_from_prefixed_canonical_path(self):
        source = PLUGIN.read_text(encoding='utf-8')

        self.assertIn(
            'oenginecons.FileLocations.EXTERNAL_TRUSTSTORE',
            source,
        )
        self.assertIn('truststore.endswith(canonical_truststore)', source)
        self.assertIn('truststore = canonical_truststore', source)
        self.assertIn(
            'os.makedirs(truststore_parent, mode=0o750, exist_ok=True)',
            source,
        )
        self.assertIn('os.path.islink(truststore_parent)', source)


if __name__ == '__main__':
    unittest.main()
