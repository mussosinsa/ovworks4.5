#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#

"""Security audit timer setup plugin."""

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
    """Enable the packaged systemd security-audit timer.

    On by default: the scheduled audit is the run nobody is watching, and a
    timer left disabled runs no audit and puts nothing in the event list.
    Set OVESETUP_SECURITY_AUDIT/enableTimer=bool:False to leave it off.
    """

    _TIMER_SERVICE = 'ovirt-engine-security-audit.timer'

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.command.detect('systemctl')
        self.environment.setdefault('OVESETUP_SECURITY_AUDIT/enableTimer', True)

    @plugin.event(
        stage=plugin.Stages.STAGE_CLOSEUP,
        before=(oengcommcons.Stages.CORE_ENGINE_START,),
        condition=lambda self: (
            self.environment[oenginecons.CoreEnv.ENABLE] and
            self.environment['OVESETUP_SECURITY_AUDIT/enableTimer'] and
            not self.environment[osetupcons.CoreEnv.DEVELOPER_MODE]
        ),
    )
    def _enable_timer(self):
        self.logger.info(_('Enabling scheduled security audit timer'))
        systemd_timer.enable_timer(self, self._TIMER_SERVICE)
