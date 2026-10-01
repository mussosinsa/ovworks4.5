#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#

"""Audit record storage watch timer setup plugin."""

import gettext

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


# vim: expandtab tabstop=4 shiftwidth=4
