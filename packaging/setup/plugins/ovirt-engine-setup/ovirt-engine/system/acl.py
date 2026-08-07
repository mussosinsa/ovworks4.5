#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""Engine ACL and sudoers adjustments."""


import gettext
import os
import re

from otopi import constants as otopicons
from otopi import filetransaction
from otopi import plugin
from otopi import util

from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """Engine ACL and sudoers adjustments plugin."""

    _AIDE_CONFIG_PATH = '/etc/aide.conf'
    _AIDE_EXCLUSIONS_BEGIN = '# BEGIN OVIRT-ENGINE MANAGED EXCLUSIONS'
    _AIDE_EXCLUSIONS_END = '# END OVIRT-ENGINE MANAGED EXCLUSIONS'
    _AIDE_EXCLUSIONS = (
        # Files modified by approved engine-setup client-control changes.
        r'!/etc/httpd/conf\.d/z-ovirt-engine-proxy\.conf$',
        r'!/etc/ovirt-engine/encryptor/config\.json$',
        r'!/etc/ovirt-engine/engine\.conf\.d/99-limit-user-sessions\.conf$',
        # Runtime, log, cache, and generated integrity data.
        r'!/run/ovirt-engine(/.*)?$',
        r'!/var/run/ovirt-engine(/.*)?$',
        r'!/var/log/ovirt-engine(/.*)?$',
        r'!/var/cache/ovirt-engine(/.*)?$',
        r'!/var/tmp/ovirt-engine(/.*)?$',
        r'!/var/lib/ovirt-engine/jboss_runtime(/.*)?$',
        r'!/var/lib/ovirt-engine/timer-service-data(/.*)?$',
        r'!/var/lib/ovirt-engine/security/integrity-baseline\.sha256$',
        r'!/tmp/ovirt-integrity-check\.log$',
        r'!/tmp/ovirt-security-audit-results\.json$',
        r'!/tmp/ovirt-security-audit-.*$',
        r'!/tmp/ovirt-jar-checksums\..*$',
    )

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.command.detect('setfacl')

    def _aide_config_with_exclusions(self, content):
        managed_block_pattern = re.compile(
            r'\n?' + re.escape(self._AIDE_EXCLUSIONS_BEGIN) +
            r'.*?' + re.escape(self._AIDE_EXCLUSIONS_END) + r'\n?',
            re.DOTALL,
        )
        content = managed_block_pattern.sub('\n', content).rstrip()
        managed_block = '\n'.join(
            (self._AIDE_EXCLUSIONS_BEGIN,) +
            self._AIDE_EXCLUSIONS +
            (self._AIDE_EXCLUSIONS_END,)
        )
        return content + '\n\n' + managed_block + '\n'

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        condition=lambda self: (
            self.environment[oenginecons.CoreEnv.ENABLE] and
            not self.environment[
                osetupcons.CoreEnv.DEVELOPER_MODE
            ]
        ),
    )
    def _configure_aide_exclusions(self):
        if not os.path.exists(self._AIDE_CONFIG_PATH):
            self.logger.info(
                _('Skipping AIDE exclusions; file is missing: %s'),
                self._AIDE_CONFIG_PATH,
            )
            return

        with open(self._AIDE_CONFIG_PATH, encoding='utf-8') as config_file:
            content = config_file.read()
        self.environment[otopicons.CoreEnv.MAIN_TRANSACTION].append(
            filetransaction.FileTransaction(
                name=self._AIDE_CONFIG_PATH,
                mode=0o600,
                owner='root',
                enforcePermissions=True,
                content=self._aide_config_with_exclusions(content),
                modifiedList=self.environment[
                    otopicons.CoreEnv.MODIFIED_FILES
                ],
            )
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_CLOSEUP,
        condition=lambda self: (
            self.environment[oenginecons.CoreEnv.ENABLE] and
            not self.environment[
                osetupcons.CoreEnv.DEVELOPER_MODE
            ]
        ),
    )
    def _closeup(self):
        sudoers_path = '/etc/sudoers.d/ovirt-aide'
        sudoers_content = (
            'ovirt ALL=(root) NOPASSWD: /usr/sbin/aide --check\n'
        )
        with open(sudoers_path, 'w', encoding='utf-8') as sudoers_file:
            sudoers_file.write(sudoers_content)
        os.chmod(sudoers_path, 0o440)

        backup_sudoers_path = '/etc/sudoers.d/ovirt-backup'
        backup_sudoers_content = (
            'ovirt ALL=(root) NOPASSWD: '
            '/usr/share/ovirt-engine/bin/all-backup.sh *, '
            '/usr/share/ovirt-engine/bin/audit-log-backup.py backup *, '
            '/usr/share/ovirt-engine/bin/audit-log-backup.py restore *, '
            '/usr/share/ovirt-engine/bin/configure-audit-log-remote.py *, '
            '/usr/share/ovirt-engine/bin/engine-backup-root.sh *\n'
        )
        with open(
            backup_sudoers_path,
            'w',
            encoding='utf-8',
        ) as sudoers_file:
            sudoers_file.write(backup_sudoers_content)
        os.chmod(backup_sudoers_path, 0o440)

        engine_proxy_conf = oenginecons.FileLocations.HTTPD_CONF_OVIRT_ENGINE
        session_limit_conf = os.path.join(
            oenginecons.FileLocations.OVIRT_ENGINE_SYSCONFDIR,
            'engine.conf.d',
            '99-limit-user-sessions.conf',
        )
        aide_conf = self._AIDE_CONFIG_PATH

        self._set_acl_if_exists(engine_proxy_conf, 'rw')
        self._set_acl_if_exists(session_limit_conf, 'rw')
        self._set_acl_if_exists(aide_conf, 'r')

    def _set_acl_if_exists(self, path, permissions):
        if not os.path.exists(path):
            self.logger.info(
                _('Skipping ACL update; file is missing: %s'),
                path,
            )
            return
        self.execute(
            args=[
                self.command.get('setfacl'),
                '-m',
                'u:ovirt:{permissions}'.format(
                    permissions=permissions,
                ),
                path,
            ],
        )


# vim: expandtab tabstop=4 shiftwidth=4
