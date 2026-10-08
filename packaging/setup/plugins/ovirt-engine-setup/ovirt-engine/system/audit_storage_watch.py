#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#

"""Audit record storage watch timer setup plugin."""

import gettext
import json

from otopi import plugin
from otopi import util

from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons
from ovirt_engine_setup.engine_common import constants as oengcommcons

from . import systemd_timer


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """Enable the timer that watches the storage under the audit records.

    The engine watches the same storage while it runs, but a database whose
    file system fills up can stop the engine; the timer keeps writing the
    levels to syslog without it. Answer False to
    OVESETUP_AUDIT_STORAGE_WATCH/enableTimer to leave it off.
    """

    _TIMER_SERVICE = 'ovirt-engine-audit-storage-watch.timer'
    _HELPER = '/usr/share/ovirt-engine/bin/audit-storage-usage.py'

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.command.detect('systemctl')
        self.environment.setdefault(
            'OVESETUP_AUDIT_STORAGE_WATCH/enableTimer',
            True,
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_CLOSEUP,
        before=(oengcommcons.Stages.CORE_ENGINE_START,),
        condition=lambda self: (
            self.environment[oenginecons.CoreEnv.ENABLE] and
            self.environment['OVESETUP_AUDIT_STORAGE_WATCH/enableTimer'] and
            not self.environment[osetupcons.CoreEnv.DEVELOPER_MODE]
        ),
    )
    def _enable_timer(self):
        self.logger.info(_('Enabling audit record storage watch timer'))
        systemd_timer.enable_timer(self, self._TIMER_SERVICE)

    @plugin.event(
        stage=plugin.Stages.STAGE_CLOSEUP,
        before=(oengcommcons.Stages.CORE_ENGINE_START,),
        condition=lambda self: (
            self.environment[oenginecons.CoreEnv.ENABLE] and
            not self.environment[osetupcons.CoreEnv.DEVELOPER_MODE]
        ),
    )
    def _check_storage_layout(self):
        """Put the emergency reserve in place and warn about the layout.

        Measured once here so that a WAL on the data file system is said
        at installation, not only in the event list later. The run also
        creates the emergency reserve file the engine keeps afterwards.
        """
        try:
            rc, stdout, _stderr = self.execute(
                (self._HELPER, 'usage', '--log-dir', '/var/log'),
                raiseOnError=False,
            )
            report = json.loads('\n'.join(stdout)) if rc == 0 else None
        except (OSError, RuntimeError, ValueError) as error:
            self.logger.debug('Audit storage layout check failed: %s', error)
            return
        if not isinstance(report, dict):
            return
        for message in layout_warnings(report):
            self.logger.warning(message)
        reserve = report.get('reserve') or {}
        if reserve.get('state') == 'present':
            self.logger.info(
                _(
                    'DB filesystem emergency reserve {path} is in place '
                    '({size} MiB); it is released automatically at the '
                    'critical usage level.'
                ).format(
                    path=reserve.get('path', ''),
                    size=int(reserve.get('size_bytes', 0)) // (1024 * 1024),
                )
            )


def layout_warnings(report):
    """What engine-setup warns about in the storage the helper measured."""
    warnings = []
    database = (report.get('filesystems') or {}).get('db') or {}
    wal = report.get('wal') or {}
    if wal.get('same_filesystem'):
        warnings.append(
            _(
                'PostgreSQL WAL ({wal}) is on the same filesystem as the '
                'database data ({mount}). If that filesystem fills up, '
                'PostgreSQL stops (PANIC) instead of failing the writes. '
                'Moving pg_wal to a separate volume is recommended.'
            ).format(
                wal=wal.get('path', 'pg_wal'),
                mount=database.get('mount') or database.get('path', ''),
            )
        )
    reserve = report.get('reserve') or {}
    if reserve.get('state') in ('insufficient', 'error', 'released'):
        warnings.append(
            _(
                'DB filesystem emergency reserve is not in place: {detail}'
            ).format(
                detail=reserve.get('detail') or _(
                    'it was released at the critical usage level; '
                    'expand the storage'
                ),
            )
        )
    return warnings


# vim: expandtab tabstop=4 shiftwidth=4
