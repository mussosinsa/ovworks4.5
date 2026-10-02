"""
test_pg_local_auth.py - Tests for ovirt_engine/pg_local_auth.py

Runs under pytest with the other library tests, and on its own:
    PYTHONPATH=packaging/pythonlib python3 packaging/pythonlib/tests/ovirt_engine/test_pg_local_auth.py
"""

import base64
import hashlib
import hmac
import unittest

from ovirt_engine import pg_local_auth as auth


# pg_hba.conf as initdb on EL writes it, after engine-setup added its rules.
SETUP_HBA = [
    '# TYPE  DATABASE        USER            ADDRESS                 METHOD',
    '',
    '# "local" is for Unix domain socket connections only',
    'local   all             all                                     peer',
    'host    engine          engine          127.0.0.1/32            scram-sha-256',
    'host    engine          engine          ::1/128                 scram-sha-256',
    '# IPv4 local connections:',
    'host    all             all             127.0.0.1/32            ident',
    '# IPv6 local connections:',
    'host    all             all             ::1/128                 ident',
    'local   replication     all                                     peer',
    'host    replication     all             127.0.0.1/32            ident',
    'host    replication     all             ::1/128                 ident',
    'host    all             all             10.0.0.0/8              trust',
]


def rules(lines):
    return [
        (r.type, r.database, r.user, r.address, r.method)
        for r in map(auth.parse, lines) if r is not None
    ]


class HardenTest(unittest.TestCase):

    def test_every_local_login_needs_a_password(self):
        hardened, changed = auth.harden_hba(SETUP_HBA)
        self.assertTrue(changed)
        self.assertEqual([
            ('local', 'all', 'ovworks_ops', '', 'peer'),
            ('local', 'all', 'all', '', 'scram-sha-256'),
            ('host', 'engine', 'engine', '127.0.0.1/32', 'scram-sha-256'),
            ('host', 'engine', 'engine', '::1/128', 'scram-sha-256'),
            ('host', 'all', 'all', '127.0.0.1/32', 'scram-sha-256'),
            ('host', 'all', 'all', '::1/128', 'scram-sha-256'),
            ('local', 'replication', 'all', '', 'scram-sha-256'),
            ('host', 'replication', 'all', '127.0.0.1/32', 'scram-sha-256'),
            ('host', 'replication', 'all', '::1/128', 'scram-sha-256'),
            # not a local login: the DBA's business, left alone
            ('host', 'all', 'all', '10.0.0.0/8', 'trust'),
        ], rules(hardened))
        self.assertTrue(auth.is_hardened(hardened))
        self.assertFalse(auth.is_hardened(SETUP_HBA))

    def test_the_monitoring_rule_comes_first_and_is_peer_with_the_map(self):
        hardened, _ = auth.harden_hba(SETUP_HBA)
        rule = next(r for r in map(auth.parse, hardened) if r is not None)
        self.assertTrue(rule.is_ops_rule())
        self.assertIn(auth.OPS_RULE, hardened)
        self.assertTrue(auth.OPS_RULE.split() == [
            'local', 'all', 'ovworks_ops', 'peer', 'map=ovworks_ops'])

    def test_comments_and_blank_lines_are_kept(self):
        hardened, _ = auth.harden_hba(SETUP_HBA)
        for line in SETUP_HBA:
            if not line.strip() or line.startswith('#'):
                self.assertIn(line, hardened)

    def test_applying_it_again_changes_nothing(self):
        hardened, _ = auth.harden_hba(SETUP_HBA)
        again, changed = auth.harden_hba(hardened)
        self.assertFalse(changed)
        self.assertEqual(hardened, again)
        self.assertEqual(1, again.count(auth.OPS_RULE))

    def test_the_netmask_form_and_options(self):
        hardened, _ = auth.harden_hba([
            'host all all 127.0.0.1 255.255.255.255 ident map=x',
            'local all postgres peer map=admins',
            'local all all md5',
        ])
        self.assertEqual([
            ('host', 'all', 'all', '127.0.0.1/255.255.255.255', 'scram-sha-256'),
            ('local', 'all', 'ovworks_ops', '', 'peer'),
            ('local', 'all', 'postgres', '', 'scram-sha-256'),
            # a password method already
            ('local', 'all', 'all', '', 'md5'),
        ], rules(hardened))
        self.assertNotIn('map=x', ' '.join(hardened))
        self.assertNotIn('map=admins', ' '.join(hardened))

    def test_a_file_without_local_rules_still_gets_the_monitoring_rule(self):
        hardened, _ = auth.harden_hba(['host all all 127.0.0.1/32 ident'])
        self.assertEqual(auth.OPS_RULE, hardened[-1])


class SetupAccessTest(unittest.TestCase):

    def test_setup_reaches_the_superuser_over_the_socket(self):
        hardened, _ = auth.harden_hba(SETUP_HBA)
        self.assertTrue(auth.superuser_needs_password(hardened))
        relaxed = auth.relax_for_setup(hardened)
        self.assertFalse(auth.superuser_needs_password(relaxed))
        self.assertEqual(
            [('local', 'all', 'ovworks_ops', '', 'peer'),
             ('local', 'all', 'all', '', 'ident'),
             ('local', 'replication', 'all', '', 'ident')],
            [r for r in rules(relaxed) if r[0] == 'local'],
        )

    def test_a_password_method_is_never_mangled(self):
        # The regular expression this replaces took the last word of the
        # line as the method: 'scram-sha-256' became 'scram-sha-ident', and
        # PostgreSQL refused to start with it.
        relaxed = auth.relax_for_setup(['local all all scram-sha-256'])
        self.assertEqual([('local', 'all', 'all', '', 'ident')], rules(relaxed))
        self.assertNotIn('scram-sha-ident', relaxed[0])

    def test_a_fresh_cluster_does_not_need_a_password(self):
        self.assertFalse(auth.superuser_needs_password(SETUP_HBA))

    def test_a_rule_for_another_user_is_not_the_superusers(self):
        self.assertTrue(auth.superuser_needs_password([
            'local all ovworks_ops peer map=ovworks_ops',
            'local all all scram-sha-256',
        ]))
        self.assertFalse(auth.superuser_needs_password([
            'local all postgres peer',
            'local all all scram-sha-256',
        ]))


class RelaxPermanentlyTest(unittest.TestCase):

    def test_back_to_peer_for_the_socket(self):
        hardened, _ = auth.harden_hba(SETUP_HBA)
        relaxed = auth.relax_permanently(hardened)
        self.assertNotIn(auth.OPS_RULE, relaxed)
        self.assertNotIn(auth.OPS_RULE_COMMENT, relaxed)
        self.assertEqual(
            [('local', 'all', 'all', '', 'peer'),
             ('local', 'replication', 'all', '', 'peer')],
            [r for r in rules(relaxed) if r[0] == 'local'],
        )


class IdentTest(unittest.TestCase):

    def test_the_map_names_root_and_ovirt(self):
        merged = auth.merge_ident([
            '# MAPNAME       SYSTEM-USERNAME         PG-USERNAME',
            'admins          alice                   postgres',
            'ovworks_ops     mallory                 ovworks_ops',
        ])
        entries = [line.split() for line in merged if line and line[0] != '#']
        self.assertEqual([
            ['admins', 'alice', 'postgres'],
            ['ovworks_ops', 'root', 'ovworks_ops'],
            ['ovworks_ops', 'ovirt', 'ovworks_ops'],
        ], entries)
        self.assertEqual(merged, auth.merge_ident(merged))
        self.assertEqual(
            ['# MAPNAME       SYSTEM-USERNAME         PG-USERNAME',
             'admins          alice                   postgres'],
            auth.remove_ident(merged),
        )


class PasswordTest(unittest.TestCase):

    def test_rules(self):
        self.assertIsNone(auth.check_password('Vm!Xk7pLq2Zt#24'))
        self.assertIsNotNone(auth.check_password('short'))
        self.assertIsNotNone(auth.check_password('Vm!Xk7pLq2Zt 24'))
        self.assertIsNotNone(auth.check_password('Vm!Xk7pLq2Zt#24é'))

    def test_the_verifier_answers_the_rfc_7677_exchange(self):
        # RFC 7677 section 3: user "user", password "pencil".
        salt = base64.b64decode('W22ZaJ0SNY7soEsUEjb6gQ==')
        verifier = auth.scram_verifier('pencil', salt=salt)
        head, keys = verifier.split('$', 1)[1].split('$')
        self.assertEqual('4096:W22ZaJ0SNY7soEsUEjb6gQ==', head)
        stored_key, server_key = (base64.b64decode(k) for k in keys.split(':'))

        auth_message = (
            b'n=user,r=rOprNGfwEbeRWgbNEkqO,'
            b'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,'
            b's=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,'
            b'c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0'
        )
        # what the server checks: the client proof recovers the client key
        proof = base64.b64decode('dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=')
        signature = hmac.new(stored_key, auth_message, hashlib.sha256).digest()
        client_key = bytes(a ^ b for a, b in zip(proof, signature))
        self.assertEqual(stored_key, hashlib.sha256(client_key).digest())
        # and what it answers with
        self.assertEqual(
            '6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=',
            base64.b64encode(
                hmac.new(server_key, auth_message, hashlib.sha256).digest()
            ).decode('ascii'),
        )

    def test_a_fresh_salt_every_time(self):
        self.assertNotEqual(
            auth.scram_verifier('Vm!Xk7pLq2Zt#24'),
            auth.scram_verifier('Vm!Xk7pLq2Zt#24'),
        )


class StatementsTest(unittest.TestCase):

    def test_the_role_can_change_nothing(self):
        statements = ' '.join(auth.OPS_ROLE_STATEMENTS)
        self.assertIn('NOSUPERUSER', statements)
        self.assertIn('PASSWORD NULL', statements)
        self.assertIn('GRANT pg_monitor TO ovworks_ops', statements)
        self.assertNotIn('pg_write', statements)
        self.assertNotIn('ALL PRIVILEGES', statements)

    def test_the_verification_query_skips_only_the_monitoring_rule(self):
        query = auth.PASSWORDLESS_RULES_QUERY
        self.assertIn("auth_method IN ('peer', 'ident', 'trust')", query)
        self.assertIn("user_name = ARRAY['ovworks_ops']", query)
        self.assertIn("options = ARRAY['map=ovworks_ops']", query)


if __name__ == '__main__':
    unittest.main()
