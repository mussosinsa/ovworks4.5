#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""The AIDE rules engine-setup manages, and the block they live in.

engine-setup writes the block and engine-cleanup takes it out again, and those run from
different plugin trees, so what the block is and how it is recognised belongs to neither of
them.
"""


import re


from otopi import util


@util.export
class Aide(object):
    """What engine-setup manages inside /etc/aide.conf."""

    CONFIG_PATH = '/etc/aide.conf'

    BEGIN = '# BEGIN OVIRT-ENGINE MANAGED EXCLUSIONS'
    END = '# END OVIRT-ENGINE MANAGED EXCLUSIONS'

    # What AIDE measures the installation against.
    #
    # Files the engine and engine-setup rewrite in the course of approved work are watched for
    # ownership and permissions rather than left out: excluded outright, a file could be made
    # world-writable or given away and nothing would report it. Only what carries no executable
    # content and gains a file per run - the uninstall records - is left out altogether.
    RULES = (
        '### oVirt Specific Monitoring Rules ###',
        '',
        '# For files whose content legitimately changes but whose ownership and permissions',
        '# must not. Not an exclusion: a file made world-writable, given away or relabelled is',
        '# still reported.',
        'OVIRT_PERMS = p+u+g+acl+selinux+xattrs',
        '',
        '# --- Engine program: does not change between upgrades ---',
        '/usr/share/ovirt-engine/ NORMAL',
        '/usr/share/ovirt-engine-wildfly/ NORMAL',
        '/usr/share/ovirt-engine-keycloak/ NORMAL',
        '/usr/share/ovirt-engine-dwh/ NORMAL',
        '/usr/share/ovirt-engine-extension-aaa-jdbc/ NORMAL',
        '/usr/share/ovirt-cockpit-sso/ NORMAL',
        '',
        '# --- Engine configuration ---',
        '/etc/ovirt-engine/ NORMAL',
        '',
        '# Rewritten by engine-setup on every run',
        r'/etc/ovirt-engine/engine\.conf\.d/[12][0-9]-setup-.*\.conf$ OVIRT_PERMS',
        r'/etc/ovirt-engine/aaa/.*\.properties$ OVIRT_PERMS',
        r'/etc/ovirt-engine/extensions\.d/internal-auth[nz]\.properties$ OVIRT_PERMS',
        '# A file per run and no executable content, so permissions would report it too',
        r'!/etc/ovirt-engine/uninstall\.d/',
        '',
        '# Rewritten by the engine when a change is applied from the screen',
        r'/etc/ovirt-engine/encryptor/config\.json$ OVIRT_PERMS',
        r'/etc/ovirt-engine/engine\.conf\.d/99-limit-user-sessions\.conf$ OVIRT_PERMS',
        '',
        '# Secrets an administrator rotates',
        r'/etc/ovirt-engine/encryptor/passphrase$ OVIRT_PERMS',
        r'/etc/ovirt-engine/encryptor/vault-token$ OVIRT_PERMS',
        r'/etc/ovirt-engine/encryptor/private_pkcs8\.der$ OVIRT_PERMS',
        '',
        '# --- Certificates ---',
        '/etc/pki/ovirt-engine/ NORMAL',
        '# Renewed on expiry and replaced when an external certificate is applied',
        r'/etc/pki/ovirt-engine/certs/apache\.cer$ OVIRT_PERMS',
        r'/etc/pki/ovirt-engine/keys/apache\.key\.nopass$ OVIRT_PERMS',
        r'/etc/pki/ovirt-engine/apache-ca\.pem$ OVIRT_PERMS',
        '',
        '# --- Web server ---',
        '/etc/httpd CONTENT_EX',
        '# Rewritten by the engine when the registered terminal addresses are changed',
        r'/etc/httpd/conf\.d/z-ovirt-engine-proxy\.conf$ OVIRT_PERMS',
        '',
        '# --- Written by the engine as it runs ---',
        '!/var/lib/ovirt-engine/',
        '!/var/log/ovirt-engine/',
        '!/var/cache/ovirt-engine/',
        '!/var/tmp/ovirt-engine/',
        '!/run/ovirt-engine/',
        '!/var/run/ovirt-engine/',
    )

    _BLOCK = re.compile(
        r'\n?' + re.escape(BEGIN) + r'.*?' + re.escape(END) + r'\n?',
        re.DOTALL,
    )

    @classmethod
    def without_block(cls, content):
        """@return the file as it was before engine-setup wrote to it"""
        return cls._BLOCK.sub('\n', content).rstrip() + '\n'

    @classmethod
    def with_block(cls, content):
        """@return the file with the managed block, replacing any block already in it"""
        return '{content}\n\n{block}\n'.format(
            content=cls.without_block(content).rstrip(),
            block='\n'.join((cls.BEGIN,) + cls.RULES + (cls.END,)),
        )


# vim: expandtab tabstop=4 shiftwidth=4
