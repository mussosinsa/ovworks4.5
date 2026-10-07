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
import shutil

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

    # Where the security verification keeps its state: the audit result the start gate reads,
    # the record of a start it refused, the integrity baseline and the cryptography events.
    _SECURITY_STATE_DIRS = (
        '/var/lib/ovirt-engine/security',
        '/var/lib/ovirt-engine/security/crypto-events',
    )
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
        stage=plugin.Stages.STAGE_CLOSEUP,
        name=oaide.Aide.SUDOERS_WRITTEN_EVENT,
        condition=lambda self: (
            self.environment[oenginecons.CoreEnv.ENABLE] and
            not self.environment[
                osetupcons.CoreEnv.DEVELOPER_MODE
            ]
        ),
    )
    def _closeup(self):
        self._ensure_security_state_dirs()
        self._repair_crypto_event_spool()

        sudoers_path = '/etc/sudoers.d/ovirt-aide'
        # Exactly the commands the integrity verification runs, with their arguments: the check
        # of the baseline's seal, and AIDE against its own configuration (integrity_baseline.py).
        # '=' is escaped: sudoers reads it as syntax otherwise.
        sudoers_content = (
            'ovirt ALL=(root) NOPASSWD: {seal}, {check}\n'
        ).format(
            seal=' '.join(oaide.Aide.verify_seal_command()),
            check=' '.join(oaide.Aide.check_command()).replace('=', '\\='),
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
            '/usr/share/ovirt-engine/bin/audit-log-backup.py purge *, '
            '/usr/share/ovirt-engine/bin/audit-storage-usage.py usage *, '
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
        self._set_acl_if_exists(engine_proxy_conf, 'rw')
        self._set_acl_if_exists(session_limit_conf, 'rw')

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

    def _ensure_security_state_dirs(self):
        """Makes the security state directories the engine's own, creating them if needed.

        The start gate writes its result into the first of them, so a directory the engine
        cannot write is not an inconvenience: the gate cannot record a verdict, the engine does
        not start, and the only thing said about it is "Permission denied". That happens
        whenever anything running as root created the directory first - an audit run by hand,
        or an earlier engine-setup - because the directory is then root's.

        Corrected here rather than only created, so that running engine-setup repairs an
        installation this has already happened to.
        """
        engine_user = self.environment[osetupcons.SystemEnv.USER_ENGINE]
        engine_group = self.environment[osetupcons.SystemEnv.GROUP_ENGINE]
        for directory in self._SECURITY_STATE_DIRS:
            try:
                os.makedirs(directory, mode=0o700, exist_ok=True)
                shutil.chown(directory, user=engine_user, group=engine_group)
                os.chmod(directory, 0o700)
            except OSError as e:
                # Said rather than raised: the rest of engine-setup is not made to fail by it,
                # and the engine failing to start says so much more loudly.
                self.logger.warning(
                    _(
                        'Could not give {directory} to {user}: {error}. The security '
                        'verification will not be able to record its result there.'
                    ).format(directory=directory, user=engine_user, error=e)
                )

    def _repair_crypto_event_spool(self):
        """Gives the engine the cryptography events root left behind as root's own.

        Before cryptoevents gave the entries it writes as root to the spool's owner, every event
        engine-setup, kek_agent or the encryptor recorded was root's and 0600. The engine could
        not open it and set it aside in rejected/ as unreadable - the key creations among them.
        Those, and any still waiting, are given to the engine and put back to be recorded.
        """
        spool = self._SECURITY_STATE_DIRS[1]
        rejected = os.path.join(spool, 'rejected')
        engine_user = self.environment[osetupcons.SystemEnv.USER_ENGINE]
        engine_group = self.environment[osetupcons.SystemEnv.GROUP_ENGINE]
        restored = 0
        for directory in (spool, rejected):
            try:
                names = sorted(os.listdir(directory))
            except OSError:
                continue
            for name in names:
                path = os.path.join(directory, name)
                if name.startswith('.') or not name.endswith('.json'):
                    continue
                try:
                    if os.lstat(path).st_uid != 0 or os.path.islink(path):
                        continue
                    shutil.chown(path, user=engine_user, group=engine_group)
                    if directory == rejected:
                        target = os.path.join(spool, name)
                        if os.path.exists(target):
                            continue
                        os.rename(path, target)
                        restored += 1
                except OSError as e:
                    self.logger.warning(
                        _('Could not give {path} to {user}: {error}').format(
                            path=path, user=engine_user, error=e,
                        )
                    )
        if restored:
            self.logger.info(
                _(
                    'Returned {count} cryptography event(s) the engine could not read '
                    'to be recorded'
                ).format(count=restored)
            )

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
