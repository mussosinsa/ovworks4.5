"""Password authentication for local PostgreSQL connections.

A PostgreSQL cluster created by initdb lets any operating system account into
the database account of the same name over the local socket, without asking
for anything (``local all all peer``).  So ``su - postgres`` followed by
``psql engine`` opens the engine database as the database superuser, and the
database never identifies or authenticates who that is.

Hardening turns every rule that lets a local connection in without a password
- ``peer``, ``ident`` and ``trust`` on the local socket and on the loopback
addresses - into ``scram-sha-256``.  ``psql`` then asks for the database
password of the role it connects as, and the ``postgres`` role must have one.

What the engine runs unattended - the security verification and the storage
watch - cannot type a password.  They connect as ``ovworks_ops``: a role that
can read settings and statistics (``pg_monitor``) and the authentication rules,
and can change nothing.  It is reached only through peer authentication, only
from the operating system accounts ``root`` and ``ovirt`` (the ``ovworks_ops``
map in ``pg_ident.conf``), and has no password, so it cannot be logged into
any other way.

engine-setup itself still needs the superuser for provisioning, extensions and
PostgreSQL upgrades.  It reopens peer access for the duration of that work, as
it always has, and puts the hardened rules back afterwards
(``relax_for_setup``).

Everything here works on the lines of the files, so it can be tested without a
database and shared by engine-setup and ``ovirt-engine-db-local-auth``.
"""

import base64
import hashlib
import hmac
import re

from ovirt_engine import csprng


OPS_ROLE = 'ovworks_ops'
IDENT_MAP = 'ovworks_ops'
OPS_OS_USERS = ('root', 'ovirt')

SCRAM = 'scram-sha-256'
PASSWORDLESS_METHODS = frozenset(('peer', 'ident', 'trust'))
LOOPBACK_ADDRESSES = frozenset((
    '127.0.0.1/32',
    '127.0.0.0/8',
    '::1/128',
    'localhost',
    'samehost',
))
HOST_TYPES = frozenset((
    'host',
    'hostssl',
    'hostnossl',
    'hostgssenc',
    'hostnogssenc',
))

OPS_RULE = '{type:7} {database:15} {user:15} {address:23} {method}'.format(
    type='local',
    database='all',
    user=OPS_ROLE,
    address='',
    method='peer map={map}'.format(map=IDENT_MAP),
)

OPS_RULE_COMMENT = (
    '# ovirt-engine: unattended monitoring only (read-only role, '
    'root/ovirt via pg_ident.conf); every other local login needs a password'
)

IDENT_COMMENT = '# ovirt-engine: OS accounts that may log in as {role}'.format(
    role=OPS_ROLE,
)

# Run as the database superuser. The role can log in, but only through the
# peer rule above: it has no password, so no password rule lets it in.
OPS_ROLE_STATEMENTS = (
    (
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles "
        "WHERE rolname = '{role}') THEN "
        "CREATE ROLE {role} LOGIN; "
        "END IF; "
        "END $$"
    ).format(role=OPS_ROLE),
    (
        'ALTER ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
        'NOREPLICATION NOBYPASSRLS PASSWORD NULL'
    ).format(role=OPS_ROLE),
    'GRANT pg_monitor TO {role}'.format(role=OPS_ROLE),
    'GRANT SELECT ON pg_catalog.pg_hba_file_rules TO {role}'.format(
        role=OPS_ROLE,
    ),
    (
        'GRANT EXECUTE ON FUNCTION pg_catalog.pg_hba_file_rules() '
        'TO {role}'
    ).format(role=OPS_ROLE),
)

# The local rules that still let someone in without a password, as the
# security verification reads them back from the running server.
PASSWORDLESS_RULES_QUERY = (
    "SELECT line_number || ':' || type || ' ' || "
    "array_to_string(database, ',') || ' ' || "
    "array_to_string(user_name, ',') || ' ' || "
    "coalesce(address, '') || ' ' || auth_method "
    "FROM pg_catalog.pg_hba_file_rules "
    "WHERE error IS NULL "
    "AND auth_method IN ('peer', 'ident', 'trust') "
    "AND (type = 'local' OR address IN "
    "('127.0.0.1', '::1', 'samehost', 'localhost')) "
    "AND NOT (type = 'local' AND user_name = ARRAY['{role}'] "
    "AND auth_method = 'peer' "
    "AND options = ARRAY['map={map}']) "
    "ORDER BY line_number"
).format(role=OPS_ROLE, map=IDENT_MAP)

# There is no database role named root, and none is made: psql run by root
# would otherwise log in as "root" and fail with "role root does not exist"
# instead of asking for anything. This makes the postgres role root's default,
# so that "psql engine" run by root asks for the postgres password entered in
# engine-setup, exactly like "psql -U postgres engine" and "su - postgres;
# psql engine". Read by login shells and, on RHEL, interactive shells
# (/etc/bashrc); services do not read it. An explicit PGUSER or -U wins.
ROOT_PROFILE = '/etc/profile.d/ovirt-engine-psql.sh'
ROOT_PROFILE_CONTENT = (
    '# ovirt-engine: local PostgreSQL logins need a password. There is no\n'
    '# database role named root, so psql run by root logs in as the postgres\n'
    '# role and asks for the postgres password set in engine-setup.\n'
    'if [ "$(id -u)" = "0" ] && [ -z "${PGUSER:-}" ]; then\n'
    '    export PGUSER=postgres\n'
    'fi\n'
)

MIN_PASSWORD_LENGTH = 14
SCRAM_ITERATIONS = 4096

_MASK = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]+$')


class Rule(object):
    """One authentication rule of pg_hba.conf."""

    def __init__(self, fields):
        self.fields = fields
        self.type = fields[0]
        if self.type == 'local':
            self.method_index = 3
            self.address = ''
        else:
            # host DATABASE USER ADDRESS [MASK] METHOD [OPTIONS]
            self.address = fields[3] if len(fields) > 3 else ''
            self.method_index = 4
            if (
                len(fields) > 5 and
                '/' not in self.address and
                _MASK.match(fields[4]) is not None
            ):
                self.address = '{0}/{1}'.format(fields[3], fields[4])
                self.method_index = 5

    @property
    def database(self):
        return self.fields[1]

    @property
    def user(self):
        return self.fields[2]

    @property
    def method(self):
        if self.method_index < len(self.fields):
            return self.fields[self.method_index]
        return None

    def is_local_access(self):
        if self.type == 'local':
            return True
        address = self.address.split('/', 1)[0]
        return self.type in HOST_TYPES and (
            self.address in LOOPBACK_ADDRESSES or
            address.startswith('127.') or
            address == '::1'
        )

    def is_ops_rule(self):
        return (
            self.type == 'local' and
            self.user == OPS_ROLE and
            self.method == 'peer' and
            self.fields[self.method_index + 1:] == [
                'map={map}'.format(map=IDENT_MAP),
            ]
        )

    def with_method(self, method):
        """The rule with another method, and without the old one's options."""
        fields = self.fields[:self.method_index] + [method]
        if self.type == 'local':
            return '{0:7} {1:15} {2:15} {3:23} {4}'.format(
                fields[0], fields[1], fields[2], '', method,
            )
        return '{0:7} {1:15} {2:15} {3:23} {4}'.format(
            fields[0],
            fields[1],
            fields[2],
            ' '.join(fields[3:self.method_index]),
            method,
        )


def parse(line):
    """The rule a line of pg_hba.conf holds, or None for anything else."""
    content = line.split('#', 1)[0].strip()
    if not content:
        return None
    fields = content.split()
    if fields[0] != 'local' and fields[0] not in HOST_TYPES:
        # include directives and anything this does not understand
        return None
    rule = Rule(fields)
    if rule.method is None:
        return None
    return rule


def harden_hba(lines):
    """Requires a password for every local login but the monitoring role's.

    Returns the new lines, and whether anything changed. Applying it twice
    gives the same lines as applying it once.
    """
    result = []
    inserted = False
    for line in lines:
        if line.strip() == OPS_RULE_COMMENT:
            continue
        rule = parse(line)
        if rule is not None and rule.is_ops_rule():
            continue
        if rule is not None and rule.type == 'local' and not inserted:
            result.append(OPS_RULE_COMMENT)
            result.append(OPS_RULE)
            inserted = True
        if (
            rule is not None and
            rule.is_local_access() and
            rule.method in PASSWORDLESS_METHODS
        ):
            line = rule.with_method(SCRAM)
        result.append(line)
    if not inserted:
        result.append(OPS_RULE_COMMENT)
        result.append(OPS_RULE)
    return result, result != list(lines)


def relax_for_setup(lines):
    """Lets the operating system user postgres in over the local socket again.

    What engine-setup has always done for the time it works as the database
    superuser: every local rule becomes ``ident`` (on a socket, the same as
    ``peer``). The monitoring rule is left as it is.
    """
    result = []
    for line in lines:
        rule = parse(line)
        if (
            rule is not None and
            rule.type == 'local' and
            not rule.is_ops_rule()
        ):
            line = rule.with_method('ident')
        result.append(line)
    return result


def relax_permanently(lines):
    """Undoes ``harden_hba`` for the local socket: back to ``peer``.

    For an administrator who has to give up password authentication for
    local logins. Loopback rules keep their passwords.
    """
    result = []
    for line in lines:
        if line.strip() == OPS_RULE_COMMENT:
            continue
        rule = parse(line)
        if rule is not None and rule.is_ops_rule():
            continue
        if (
            rule is not None and
            rule.type == 'local' and
            rule.method == SCRAM
        ):
            line = rule.with_method('peer')
        result.append(line)
    return result


def is_hardened(lines):
    """Whether no local login gets in without a password, but the ops role."""
    for line in lines:
        rule = parse(line)
        if (
            rule is not None and
            rule.is_local_access() and
            rule.method in PASSWORDLESS_METHODS and
            not rule.is_ops_rule()
        ):
            return False
    return True


def superuser_needs_password(lines):
    """Whether the first local rule that applies to postgres asks for one."""
    for line in lines:
        rule = parse(line)
        if rule is None or rule.type != 'local':
            continue
        users = rule.user.split(',')
        databases = rule.database.split(',')
        if (
            ('all' in users or 'postgres' in users) and
            ('all' in databases or 'template1' in databases)
        ):
            return rule.method not in PASSWORDLESS_METHODS
    # no rule at all: PostgreSQL rejects the connection
    return True


def merge_ident(lines):
    """pg_ident.conf with the monitoring map, and nothing else of it."""
    result = []
    for line in lines:
        fields = line.split('#', 1)[0].split()
        if line.strip() == IDENT_COMMENT:
            continue
        if fields and fields[0] == IDENT_MAP:
            continue
        result.append(line)
    result.append(IDENT_COMMENT)
    for user in OPS_OS_USERS:
        result.append('{0:15} {1:23} {2}'.format(IDENT_MAP, user, OPS_ROLE))
    return result


def remove_ident(lines):
    return [
        line for line in lines
        if line.strip() != IDENT_COMMENT and
        line.split('#', 1)[0].split()[:1] != [IDENT_MAP]
    ]


def check_password(password):
    """Why a new superuser password cannot be used, or None.

    Printable ASCII only: PostgreSQL normalizes other passwords (SASLprep)
    before hashing them, and the verifier made here would not match.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return 'at least {n} characters'.format(n=MIN_PASSWORD_LENGTH)
    if any(not (' ' < c <= '~') for c in password):
        return 'printable ASCII characters only, no blanks'
    return None


def scram_verifier(password, salt=None, iterations=SCRAM_ITERATIONS):
    """The SCRAM-SHA-256 verifier PostgreSQL stores for a password.

    Setting the verifier rather than the password keeps the password out of
    the server log and the statement, whatever log_statement is set to.
    """
    if salt is None:
        salt = csprng.token_bytes(16)
    salted = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt, iterations,
    )
    client_key = hmac.new(salted, b'Client Key', hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b'Server Key', hashlib.sha256).digest()
    return 'SCRAM-SHA-256${i}:{salt}${stored}:{server}'.format(
        i=iterations,
        salt=base64.b64encode(salt).decode('ascii'),
        stored=base64.b64encode(stored_key).decode('ascii'),
        server=base64.b64encode(server_key).decode('ascii'),
    )


# vim: expandtab tabstop=4 shiftwidth=4
