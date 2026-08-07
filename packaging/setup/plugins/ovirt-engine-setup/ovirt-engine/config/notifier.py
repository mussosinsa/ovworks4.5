#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""Notifier plugin."""


import gettext

from otopi import plugin
from otopi import util

from ovirt_engine import configfile

from ovirt_engine_setup.engine import constants as oenginecons

from ovirt_setup_lib import dialog


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """Notifier plugin."""

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.environment.setdefault(
            oenginecons.ConfigEnv.IGNORE_VDS_GROUP_IN_NOTIFIER,
            None
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_VALIDATION,
        condition=lambda self: self.environment[
            oenginecons.CoreEnv.ENABLE
        ] and not self.environment[
            oenginecons.ConfigEnv.IGNORE_VDS_GROUP_IN_NOTIFIER
        ],
    )
    def _validation(self):
        config = configfile.ConfigFile(
            (
                oenginecons.FileLocations.OVIRT_ENGINE_NOTIFIER_SERVICE_CONFIG,
            ),
        )
        filterStr = config.get('FILTER')
        self.logger.debug('filterStr: %s', filterStr)
        if filterStr is not None and 'VDS_GROUP' in filterStr:
            ans = dialog.queryBoolean(
                dialog=self.dialog,
                name='OVESETUP_WAIT_NOTIFIER_FILTER',
                note=_(
                    'Setup이 {conf}.d/*.conf 의 engine-notifier 설정 파일에서 '
                    '"VDS_GROUP" 문자열을 포함한 필터를 찾았습니다.\n'
                    '클러스터 관련 이벤트 알림을 받으려면 notifier 설정 전반에서 '
                    '"VDS_GROUP"을 "CLUSTER"로 수동 변경해야 합니다.\n'
                    '계속 진행하시겠습니까?\n'
                    '("아니오"를 선택하면 업그레이드가 중단됩니다 '
                    '(@VALUES@) [@DEFAULT@]: '
                ).format(
                    conf=(
                        oenginecons.FileLocations.
                        OVIRT_ENGINE_NOTIFIER_SERVICE_CONFIG
                    ),
                ),
                prompt=True,
                default=False,
            )
            self.environment[
                oenginecons.ConfigEnv.IGNORE_VDS_GROUP_IN_NOTIFIER
            ] = ans
            if not ans:
                raise RuntimeError(_('Aborted by user'))


# vim: expandtab tabstop=4 shiftwidth=4
