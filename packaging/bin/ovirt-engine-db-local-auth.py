#!/usr/bin/python3
"""Require a password for local logins to the engine's PostgreSQL.

A cluster created by initdb lets the operating system user postgres into the
database superuser over the local socket without asking anything, so
``su - postgres`` followed by ``psql engine`` opens the engine database
unidentified. engine-setup closes that on new installations; this does the
same on an installation set up before it, and can undo it.

    status    what the local rules allow now
    enable    require a password (sets the postgres password if it has none)
    disable   back to peer authentication for the local socket

Run as root on the database host. See ovirt_engine.pg_local_auth for what is
changed, and docs/db-local-authentication.md.
"""

import argparse
import datetime
import getpass
import os
import shutil
import subprocess
import sys

from ovirt_engine import pg_local_auth as auth


DEFAULT_DATA_DIRECTORY = '/var/lib/pgsql/data'
RUNUSER = '/usr/sbin/runuser'
PSQL = '/usr/bin/psql'
TIMEOUT = 30


class Failure(Exception):
    pass


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return f.read().splitlines()


def write_lines(path, lines, like):
    """Writes the file in place, with the owner and mode of ``like``."""
    with open(path, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    stat = os.stat(like)
    os.chown(path, stat.st_uid, stat.st_gid)
    os.chmod(path, stat.st_mode & 0o7777)


def backup(path):
    if not os.path.exists(path):
        return None
    copy = '{path}.{stamp}.bak'.format(
        path=path,
        stamp=datetime.datetime.now().strftime('%Y%m%d%H%M%S'),
    )
    shutil.copy2(path, copy)
    return copy


def write_root_profile():
    """Makes postgres the role psql run by root logs in as (pg_local_auth)."""
    with open(auth.ROOT_PROFILE, 'w') as f:
        f.write(auth.ROOT_PROFILE_CONTENT)
    os.chmod(auth.ROOT_PROFILE, 0o644)


def pg_ctl():
    for candidate in ('/usr/bin/pg_ctl', shutil.which('pg_ctl')):
        if candidate and os.path.exists(candidate):
            return candidate
    raise Failure('pg_ctl not found')


def reload_configuration(data_directory):
    """Rereads pg_hba.conf and pg_ident.conf. Needs no database login."""
    result = subprocess.run(
        [RUNUSER, '-u', 'postgres', '--', pg_ctl(), 'reload', '-s',
         '-D', data_directory],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=TIMEOUT,
        cwd='/',
    )
    if result.returncode != 0:
        raise Failure('PostgreSQL did not reload: %s' % result.stderr.strip())


def psql(sql, as_postgres, user=None, database='postgres', stdin=None,
         stored_passwords=True):
    """Runs one statement without ever prompting; returns (ok, out, err)."""
    command = [PSQL, '-X', '-q', '-At', '-w', '-v', 'ON_ERROR_STOP=1',
               '-d', database]
    environment = dict(os.environ)
    environment.pop('PGPASSWORD', None)
    if not stored_passwords:
        environment['PGPASSFILE'] = os.devnull
    if user:
        command += ['-U', user]
    if sql is not None:
        command += ['-c', sql]
    if as_postgres:
        command = [RUNUSER, '-u', 'postgres', '--'] + command
    result = subprocess.run(
        command,
        env=environment,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=TIMEOUT,
        cwd='/',
    )
    return result.returncode == 0, result.stdout.strip(), result.stderr.strip()


def superuser(sql, stdin=None):
    ok, out, err = psql(sql, as_postgres=True, stdin=stdin)
    if not ok:
        raise Failure(err or 'psql failed')
    return out


def ask_password():
    if not sys.stdin.isatty():
        raise Failure(
            'the postgres role has no password; run this on a terminal '
            'to set one')
    print('The postgres database role has no password. Local logins will '
          'need one from now on.')
    while True:
        password = getpass.getpass('New password for the postgres role: ')
        problem = auth.check_password(password)
        if problem:
            print('Not usable: %s.' % problem)
            continue
        if getpass.getpass('Again: ') != password:
            print('The passwords differ.')
            continue
        return password


def status(data_directory):
    hba = os.path.join(data_directory, 'pg_hba.conf')
    lines = read_lines(hba)
    if not lines:
        raise Failure('%s not found' % hba)
    print('pg_hba.conf: %s' % hba)
    for line in lines:
        rule = auth.parse(line)
        if rule is not None and rule.is_local_access():
            mark = (
                'monitoring' if rule.is_ops_rule()
                else 'NO PASSWORD' if rule.method in auth.PASSWORDLESS_METHODS
                else 'password'
            )
            print('  %-11s %s' % (mark, ' '.join(rule.fields)))
    hardened = auth.is_hardened(lines)
    print('local logins need a password: %s' % ('yes' if hardened else 'no'))
    return 0 if hardened else 1


def enable(data_directory):
    hba = os.path.join(data_directory, 'pg_hba.conf')
    ident = os.path.join(data_directory, 'pg_ident.conf')
    original_hba = read_lines(hba)
    if not original_hba:
        raise Failure('%s not found' % hba)
    ident_existed = os.path.exists(ident)
    profile_existed = os.path.exists(auth.ROOT_PROFILE)
    original_ident = read_lines(ident)
    saved = [backup(hba), backup(ident)]

    def restore():
        write_lines(hba, original_hba, hba)
        if ident_existed:
            write_lines(ident, original_ident, ident)
        elif os.path.exists(ident):
            os.remove(ident)
        if not profile_existed and os.path.exists(auth.ROOT_PROFILE):
            os.remove(auth.ROOT_PROFILE)
        reload_configuration(data_directory)

    try:
        # The superuser work below is done the way it always could be:
        # as the operating system user postgres, over the socket.
        write_lines(hba, auth.relax_for_setup(original_hba), hba)
        reload_configuration(data_directory)

        has_password = superuser(
            "SELECT rolpassword IS NOT NULL FROM pg_catalog.pg_authid "
            "WHERE rolname = 'postgres'") == 't'
        if not has_password:
            verifier = auth.scram_verifier(ask_password())
            # On standard input, so it is in no process list; a verifier,
            # so not even the server log could show the password.
            superuser(None, stdin="ALTER ROLE postgres PASSWORD '%s';\n"
                      % verifier)
        for statement in auth.OPS_ROLE_STATEMENTS:
            superuser(statement)

        hardened, _changed = auth.harden_hba(original_hba)
        write_lines(ident, auth.merge_ident(original_ident), hba)
        write_root_profile()
        write_lines(hba, hardened, hba)
        reload_configuration(data_directory)

        ok, _out, _err = psql('SELECT 1', as_postgres=True,
                              stored_passwords=False)
        if ok:
            raise Failure('postgres still logs in without a password')
        ok, _out, err = psql('SELECT 1', as_postgres=False, user=auth.OPS_ROLE)
        if not ok:
            raise Failure('the monitoring role cannot log in: %s' % err)
    except BaseException:
        restore()
        raise
    print('Local logins now need a password: su - postgres; psql engine, and '
          'psql engine or psql -U postgres engine as root, ask for the '
          'postgres role\'s.')
    print('Root shells opened before this pick it up at their next login '
          '(%s).' % auth.ROOT_PROFILE)
    pgpass = os.path.expanduser('~postgres/.pgpass')
    if os.path.exists(pgpass):
        print('Warning: %s holds stored passwords, which psql uses without '
              'asking. Remove it for the password to be asked for.' % pgpass)
    print('Previous files: %s' % ', '.join(p for p in saved if p))
    return 0


def disable(data_directory):
    hba = os.path.join(data_directory, 'pg_hba.conf')
    ident = os.path.join(data_directory, 'pg_ident.conf')
    lines = read_lines(hba)
    if not lines:
        raise Failure('%s not found' % hba)
    saved = [backup(hba), backup(ident)]
    write_lines(hba, auth.relax_permanently(lines), hba)
    if os.path.exists(ident):
        write_lines(ident, auth.remove_ident(read_lines(ident)), ident)
    if os.path.exists(auth.ROOT_PROFILE):
        os.remove(auth.ROOT_PROFILE)
    reload_configuration(data_directory)
    print('Local logins are back to peer authentication (no password).')
    print('Previous files: %s' % ', '.join(p for p in saved if p))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Require a password for local PostgreSQL logins.')
    parser.add_argument('action', choices=('status', 'enable', 'disable'))
    parser.add_argument(
        '--data-dir',
        default=os.environ.get('PGDATA', DEFAULT_DATA_DIRECTORY),
        help='PostgreSQL data directory (default: %(default)s)')
    args = parser.parse_args(argv)
    if os.geteuid() != 0 and args.action != 'status':
        print('Run as root.', file=sys.stderr)
        return 2
    try:
        return {
            'status': status,
            'enable': enable,
            'disable': disable,
        }[args.action](args.data_dir)
    except (Failure, OSError, subprocess.SubprocessError) as error:
        print('Failed: %s' % error, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
