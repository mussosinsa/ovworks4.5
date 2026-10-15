#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""The integrity verification's own AIDE configuration.

The integrity verification measures the files of the six main processes - ovirt-engine,
ovirt-engine-proxy (httpd), postgresql, ovirt-engine-dwhd, ovirt-websocket-proxy and
ovirt-provider-ovn - by exact name, and nothing else: not the operating system, not the network
configuration, not logs. It has an AIDE configuration and database of its own for that, so
that the distribution's /etc/aide.conf, which measures the whole operating system, is not what
it reports on.

The files are those of ProcessFiles.LIST_PATH, the list the self-test checks as well.
engine-setup writes the configuration and takes the baseline; engine-cleanup removes both.
engine-setup and engine-cleanup run from different plugin trees, so what the files are belongs
to neither of them.
"""


import glob as _glob
import os
import re


from otopi import util


@util.export
class ProcessFiles(object):
    """The six processes and their files, as ovworks-process-files.conf lists them."""

    LIST_PATH = '/usr/share/ovirt-engine/conf/ovworks-process-files.conf'

    class Entry(object):
        def __init__(self, process, type, flags, path):
            self.process = process
            self.type = type
            self.flags = () if flags == '-' else tuple(flags.split(','))
            self.path = path

        def has(self, flag):
            return flag in self.flags

    @classmethod
    def parse(cls, content):
        entries = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            fields = line.split()
            if len(fields) != 4:
                raise ValueError('Malformed process file entry: %s' % line)
            entries.append(cls.Entry(*fields))
        return entries

    @classmethod
    def read(cls, path=None):
        with open(path or cls.LIST_PATH, encoding='utf-8') as stream:
            return cls.parse(stream.read())


@util.export
class Aide(object):
    """The AIDE configuration and database of the integrity verification."""

    CONFIG_PATH = '/etc/ovirt-engine/aide/ovworks-aide.conf'
    # The throwaway configuration integrity_seal.py --open writes on tmpfs, pointing AIDE at the
    # decrypted baseline. --check reads this one, never the sealed CONFIG_PATH, since the baseline
    # at rest is encrypted. Fixed path, so the sudo rule carries no caller-supplied argument.
    OPEN_CONFIG_PATH = '/dev/shm/ovworks-aide.conf'

    # The closeup event that writes the sudo rule (system/acl.py). The rule is measured, so the
    # baseline (system/integrity_baseline.py) is taken after it is written.
    SUDOERS_WRITTEN_EVENT = 'osetup.engine.security.sudoers'
    DATABASE = '/var/lib/aide/ovworks.db.gz'
    DATABASE_NEW = '/var/lib/aide/ovworks.db.new.gz'
    # HMAC-SHA256 of the configuration and the database under a key from the DEK
    # (encryptor/integrity_seal.py), checked before every verification.
    SEAL = '/var/lib/aide/ovworks.db.seal'
    SEAL_TOOL = '/usr/share/ovirt-engine/encryptor/integrity_seal.py'
    PYTHON = '/usr/bin/python3'
    COMMAND = '/usr/sbin/aide'

    # The option naming the baseline AIDE reads. AIDE 0.17 renamed it from database to
    # database_in, and 0.18 dropped the old name: AIDE 0.19 (Rocky Linux 9.8) refuses
    # 'database=file:...' as "unexpected character: ':'". 0.16 knows only the old name.
    DATABASE_IN_KEY = 'database_in'
    DATABASE_IN_KEY_BEFORE_0_17 = 'database'
    _VERSION = re.compile(r'\baide\s+v?(\d+)\.(\d+)', re.IGNORECASE)
    _DATABASE_IN_LINE = re.compile(r'^(?:database|database_in)\s*=', re.MULTILINE)

    # What the engine reads to name the process of every file it reports on: a file in the
    # baseline, and one that is not (absent, or its process not installed).
    MEASURED = '#@'
    NOT_MEASURED = '#-'

    # Group names are letters and digits only: AIDE 0.19 (Rocky Linux 9.8) warns that any
    # other character in them is deprecated.
    # Content and attributes. Not the inode or the times: a package reinstall that puts back
    # the same file is not a change to it.
    CONTENT_RULE = 'OVWORKSCONTENT = p+n+u+g+s+acl+selinux+xattrs+sha512'
    # For files rewritten in approved work (by the engine from the screen, or by an
    # administrator's tool): ownership and permissions are still measured - a file made
    # world-writable or given away is reported - but not the content.
    PERMS_RULE = 'OVWORKSPERMS = p+u+g+acl+selinux+xattrs'

    # What engine-setup used to add to /etc/aide.conf, before the verification had a
    # configuration of its own. Taken out again wherever it is still found.
    LEGACY_CONFIG_PATH = '/etc/aide.conf'
    LEGACY_BEGIN = '# BEGIN OVIRT-ENGINE MANAGED EXCLUSIONS'
    LEGACY_END = '# END OVIRT-ENGINE MANAGED EXCLUSIONS'

    _LEGACY_BLOCK = re.compile(
        r'\n?' + re.escape(LEGACY_BEGIN) + r'.*?' + re.escape(LEGACY_END) + r'\n?',
        re.DOTALL,
    )

    _SPECIAL = re.compile(r'([.^$*+?()\[\]{}|\\])')

    @classmethod
    def without_legacy_block(cls, content):
        """@return /etc/aide.conf as it was before engine-setup ever wrote to it"""
        if cls.LEGACY_BEGIN not in content:
            return content
        return cls._LEGACY_BLOCK.sub('\n', content).rstrip() + '\n'

    @classmethod
    def _regex(cls, path):
        return cls._SPECIAL.sub(r'\\\1', path)

    @classmethod
    def config(cls, entries, exists=os.path.exists, expand=_glob.glob):
        """@return the AIDE configuration measuring the files of the entries that exist

        A path with a * in it (the engine's Python library, whose directory names the Python
        version) is resolved here, to each path it matches.
        """
        lines = [
            '# OV-Works integrity verification: the files of the six main processes.',
            '# Written by engine-setup from ' + ProcessFiles.LIST_PATH + '; do not edit.',
            '# Lines starting with ' + cls.MEASURED + ' name a measured file and its process,',
            '# ' + cls.NOT_MEASURED + ' one that is not measured because it is not there.',
            '',
            cls.DATABASE_IN_KEY + '=file:' + cls.DATABASE,
            'database_out=file:' + cls.DATABASE_NEW,
            'gzip_dbout=yes',
            'report_url=stdout',
            '',
            cls.CONTENT_RULE,
            cls.PERMS_RULE,
        ]
        process = None
        resolved = []
        for entry in entries:
            if '*' in entry.path:
                matches = sorted(expand(entry.path))
                for path in matches:
                    resolved.append(ProcessFiles.Entry(
                        entry.process, entry.type, ','.join(entry.flags) or '-', path))
                if matches:
                    continue
            resolved.append(entry)
        for entry in resolved:
            if entry.type == 'unit':
                continue
            if entry.process != process:
                process = entry.process
                lines.extend(('', '# --- %s ---' % process))
            if not exists(entry.path):
                lines.append('%s %s %s' % (cls.NOT_MEASURED, entry.process, entry.path))
                continue
            rule = 'OVWORKSPERMS' if entry.has('mutable') else 'OVWORKSCONTENT'
            lines.append('%s %s %s' % (cls.MEASURED, entry.process, entry.path))
            regex = cls._regex(entry.path)
            lines.append('=%s$ %s' % (regex, rule))
            if entry.has('tree'):
                lines.append('%s/ %s' % (regex, rule))
        return '\n'.join(lines) + '\n'

    @classmethod
    def version_command(cls):
        return (cls.COMMAND, '--version')

    @classmethod
    def parse_version(cls, output):
        """@return (major, minor) from what aide --version printed, or None"""
        match = cls._VERSION.search(output or '')
        return (int(match.group(1)), int(match.group(2))) if match else None

    @classmethod
    def database_key(cls, version):
        """The input database option the installed AIDE takes; the current one when unknown."""
        if version is not None and version < (0, 17):
            return cls.DATABASE_IN_KEY_BEFORE_0_17
        return cls.DATABASE_IN_KEY

    @classmethod
    def for_version(cls, content, version):
        """@return the configuration with its input database option named for that AIDE"""
        key = cls.database_key(version)
        return cls._DATABASE_IN_LINE.sub(key + '=', content)

    @classmethod
    def init_command(cls):
        return (cls.COMMAND, '--config=' + cls.CONFIG_PATH, '--init')

    @classmethod
    def seal_command(cls):
        return (cls.PYTHON, cls.SEAL_TOOL, '--seal')

    @classmethod
    def verify_seal_command(cls):
        return (cls.PYTHON, cls.SEAL_TOOL, '--verify')

    @classmethod
    def open_command(cls):
        # Verify the seal and decrypt the baseline to tmpfs for AIDE to read.
        return (cls.PYTHON, cls.SEAL_TOOL, '--open')

    @classmethod
    def close_command(cls):
        # Shred the decrypted baseline left on tmpfs.
        return (cls.PYTHON, cls.SEAL_TOOL, '--close')

    @classmethod
    def check_command(cls):
        # AIDE reads the throwaway tmpfs configuration --open wrote (which points at the decrypted
        # baseline), never the sealed on-disk configuration.
        return (cls.COMMAND, '--config=' + cls.OPEN_CONFIG_PATH, '--check')


# vim: expandtab tabstop=4 shiftwidth=4
