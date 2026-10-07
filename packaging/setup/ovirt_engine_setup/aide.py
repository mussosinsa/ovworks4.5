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
    DATABASE = '/var/lib/aide/ovworks.db.gz'
    DATABASE_NEW = '/var/lib/aide/ovworks.db.new.gz'
    COMMAND = '/usr/sbin/aide'

    # What the engine reads to name the process of every file it reports on: a file in the
    # baseline, and one that is not (absent, or its process not installed).
    MEASURED = '#@'
    NOT_MEASURED = '#-'

    # Content and attributes. Not the inode or the times: a package reinstall that puts back
    # the same file is not a change to it.
    CONTENT_RULE = 'OVWORKS_CONTENT = p+n+u+g+s+acl+selinux+xattrs+sha512'
    # For files rewritten in approved work (by the engine from the screen, or by an
    # administrator's tool): ownership and permissions are still measured - a file made
    # world-writable or given away is reported - but not the content.
    PERMS_RULE = 'OVWORKS_PERMS = p+u+g+acl+selinux+xattrs'

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
    def config(cls, entries, exists=os.path.exists):
        """@return the AIDE configuration measuring the files of the entries that exist"""
        lines = [
            '# OV-Works integrity verification: the files of the six main processes.',
            '# Written by engine-setup from ' + ProcessFiles.LIST_PATH + '; do not edit.',
            '# Lines starting with ' + cls.MEASURED + ' name a measured file and its process,',
            '# ' + cls.NOT_MEASURED + ' one that is not measured because it is not there.',
            '',
            'database=file:' + cls.DATABASE,
            'database_out=file:' + cls.DATABASE_NEW,
            'gzip_dbout=yes',
            'report_url=stdout',
            '',
            cls.CONTENT_RULE,
            cls.PERMS_RULE,
        ]
        process = None
        for entry in entries:
            if entry.type == 'unit':
                continue
            if entry.process != process:
                process = entry.process
                lines.extend(('', '# --- %s ---' % process))
            if not exists(entry.path):
                lines.append('%s %s %s' % (cls.NOT_MEASURED, entry.process, entry.path))
                continue
            rule = 'OVWORKS_PERMS' if entry.has('mutable') else 'OVWORKS_CONTENT'
            lines.append('%s %s %s' % (cls.MEASURED, entry.process, entry.path))
            regex = cls._regex(entry.path)
            lines.append('=%s$ %s' % (regex, rule))
            if entry.has('tree'):
                lines.append('%s/ %s' % (regex, rule))
        return '\n'.join(lines) + '\n'

    @classmethod
    def init_command(cls):
        return (cls.COMMAND, '--config=' + cls.CONFIG_PATH, '--init')

    @classmethod
    def check_command(cls):
        return (cls.COMMAND, '--config=' + cls.CONFIG_PATH, '--check')


# vim: expandtab tabstop=4 shiftwidth=4
