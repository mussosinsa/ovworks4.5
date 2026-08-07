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


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """Optionally enable the packaged systemd security-audit timer."""

    _TIMER_SERVICE = 'ovirt-engine-security-audit.timer'

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.environment.setdefault('OVESETUP_SECURITY_AUDIT/enableTimer', False)

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
        self.services.state(name=self._TIMER_SERVICE, state=True)
        self.services.startup(name=self._TIMER_SERVICE, state=True)
