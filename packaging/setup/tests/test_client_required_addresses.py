import ast
import importlib.util
import unittest
from pathlib import Path


SETUP = Path(__file__).parents[1]

# Loaded from its file: the tests keep a stand-in ovirt_engine_setup package of their own.
_SPEC = importlib.util.spec_from_file_location(
    'client_addresses', SETUP / 'ovirt_engine_setup/client_addresses.py')
client_addresses = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(client_addresses)

APACHE_PLUGIN = SETUP / 'plugins/ovirt-engine-setup/ovirt-engine/apache/engine.py'


class RequiredClientAddressesTest(unittest.TestCase):
    """engine-setup always keeps 127.0.0.1 and the engine host's own address on the terminal IP
    list (Require ip), whatever was answered."""

    def test_the_loopback_and_host_addresses_come_first_and_once(self):
        self.assertEqual(
            ['127.0.0.1', '192.168.40.124', '192.168.40.0/24', '192.168.40.114'],
            client_addresses.with_required_addresses(
                ['192.168.40.0/24', '127.0.0.1', '192.168.40.114', '192.168.40.124'],
                ['192.168.40.124'],
            ),
        )

    def test_an_empty_answer_still_gives_the_required_addresses(self):
        self.assertEqual(['127.0.0.1', '192.168.40.124'],
                         client_addresses.with_required_addresses(None, ['192.168.40.124']))
        self.assertEqual(['127.0.0.1'], client_addresses.with_required_addresses((), []))

    def test_the_host_address_is_what_the_fqdn_resolves_to_on_this_host(self):
        addresses = client_addresses.engine_host_addresses(
            'engine.example.com',
            resolve=lambda fqdn: ['127.0.0.1', '192.168.40.124', '10.9.9.9'],
            default_route=lambda: '192.168.40.124',
            is_host_address=lambda address: address in ('192.168.40.124', '127.0.0.1'),
        )
        # Loopback is not "the host address", and 10.9.9.9 is not this host's.
        self.assertEqual(['192.168.40.124'], addresses)

    def test_without_a_resolvable_fqdn_the_default_route_address_is_used(self):
        addresses = client_addresses.engine_host_addresses(
            None,
            resolve=lambda fqdn: [],
            default_route=lambda: '192.168.40.124',
            is_host_address=lambda address: True,
        )
        self.assertEqual(['192.168.40.124'], addresses)

    def test_nothing_usable_gives_no_host_address(self):
        self.assertEqual([], client_addresses.engine_host_addresses(
            'x', resolve=lambda fqdn: ['0.0.0.0', 'fe80::1', 'bad'],
            default_route=lambda: None, is_host_address=lambda address: True))

    def test_the_apache_plugin_writes_the_list_with_the_required_addresses(self):
        source = APACHE_PLUGIN.read_text(encoding='utf-8')
        tree = ast.parse(source)
        misc = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_misc')
        body = ast.get_source_segment(source, misc)
        self.assertIn('client_addresses.engine_host_addresses(', body)
        self.assertIn('client_addresses.with_required_addresses(', body)
        self.assertIn('osetupcons.ConfigEnv.FQDN', body)
        self.assertLess(body.index('with_required_addresses('), body.index('Require ip {address}'))


if __name__ == '__main__':
    unittest.main()
