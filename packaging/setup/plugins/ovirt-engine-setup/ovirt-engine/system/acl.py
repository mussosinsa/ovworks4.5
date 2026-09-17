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

from otopi import constants as otopicons
from otopi import filetransaction
from otopi import plugin
from otopi import util

from ovirt_engine_setup import aide as oaide
from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """Engine ACL and sudoers adjustments plugin."""

    _HTTPD_LOG_DIR = '/var/log/httpd'
    _CLIENT_ACCESS_DENIED_LOG = (
        '/var/log/httpd/ovirt-engine-admin-access-denied-audit.log'
    )

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.command.detect('setfacl')

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
        if not os.path.exists(oaide.Aide.CONFIG_PATH):
            # Said as a warning: the integrity verification measures the installation against
            # this file, so without it nothing is measured - and an integrity check that
            # checks nothing looks, in the event list, like one that found nothing wrong.
            self.logger.warning(
                _(
                    'Not configuring AIDE: {file} is missing, so the integrity '
                    'verification has no rules to check the installation against'
                ).format(file=oaide.Aide.CONFIG_PATH)
            )
            return

        with open(oaide.Aide.CONFIG_PATH, encoding='utf-8') as config_file:
            content = config_file.read()
        self.environment[otopicons.CoreEnv.MAIN_TRANSACTION].append(
            filetransaction.FileTransaction(
                name=oaide.Aide.CONFIG_PATH,
                mode=0o600,
                owner='root',
                enforcePermissions=True,
                content=oaide.Aide.with_block(content),
            )
        )
        # Not in MODIFIED_FILES, and named unremovable. engine-cleanup deletes what is in
        # MODIFIED_FILES - it does not restore it - and this file belongs to the aide package,
        # not to us. Deleting it takes the distribution's whole AIDE configuration with it, and
        # the next engine-setup then finds no file and writes no rules at all.
        self.environment[
            osetupcons.CoreEnv.UNINSTALL_UNREMOVABLE_FILES
        ].append(oaide.Aide.CONFIG_PATH)

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
        aide_conf = oaide.Aide.CONFIG_PATH

        self._set_acl_if_exists(engine_proxy_conf, 'rw')
        self._set_acl_if_exists(session_limit_conf, 'rw')
        self._set_acl_if_exists(aide_conf, 'r')

        # An address the web server turned away never reaches the engine, so what the web server
        # wrote about it is the only account of the attempt. The engine reads that file to put
        # those attempts in the event list, and /var/log/httpd is not otherwise reachable by
        # anybody but root: 'x' opens the path without opening the directory to be listed.
        #
        # The directory is what has to carry it. httpd's own logrotate rule covers this file
        # (/var/log/httpd/*log), and rotation replaces the file, taking any ACL set on it with
        # it; the directory is not replaced, and the rotated file keeps the mode of the one it
        # replaced. The ACL on the file itself is set for the case where httpd wrote it with a
        # mode the engine cannot read.
        self._set_acl_if_exists(self._HTTPD_LOG_DIR, 'x')
        self._set_acl_if_exists(self._CLIENT_ACCESS_DENIED_LOG, 'r')

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
