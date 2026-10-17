# Modified by 새올정보기술 for OV-Works (2026). Changes against oVirt Engine 4.5.6: docs/ovworks-source-change-statement.md
#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""Apache ovirt-engine plugin."""


import gettext

from otopi import constants as otopicons
from otopi import filetransaction
from otopi import plugin
from otopi import util

from ovirt_engine import util as outil

from ovirt_engine_setup import client_addresses
from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons
from ovirt_engine_setup.engine_common import constants as oengcommcons


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


_CLIENT_CONTROL_ENV = getattr(oenginecons, 'ClientControlEnv', None)
_ALLOWED_IPS_ENV = getattr(
    _CLIENT_CONTROL_ENV,
    'ALLOWED_IPS',
    'OVESETUP_CLIENT_CONTROL/allowedIps',
)


@util.export
class Plugin(plugin.PluginBase):
    """Apache ovirt-engine plugin."""

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.environment.setdefault(
            oenginecons.ApacheEnv.HTTPD_CONF_OVIRT_ENGINE,
            oenginecons.FileLocations.HTTPD_CONF_OVIRT_ENGINE
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        condition=lambda self: self.environment[
            oenginecons.CoreEnv.ENABLE
        ] and not self.environment[
            osetupcons.CoreEnv.DEVELOPER_MODE
        ],
    )
    def _misc(self):
        self.environment[oengcommcons.ApacheEnv.NEED_RESTART] = True
        # 127.0.0.1, ::1 and the engine host's own address are always on the list, whatever was
        # answered: without them the engine's components and the host itself are turned away.
        host_addresses = client_addresses.engine_host_addresses(
            self.environment.get(osetupcons.ConfigEnv.FQDN)
        )
        allowed_ips = client_addresses.with_required_addresses(
            self.environment.get(_ALLOWED_IPS_ENV),
            host_addresses,
        )
        if host_addresses:
            self.logger.info(
                _('Terminal IP list always keeps 127.0.0.1, ::1 and the engine host: {addresses}').format(
                    addresses=', '.join(host_addresses),
                )
            )
        else:
            self.logger.warning(
                _('The engine host address could not be determined; only 127.0.0.1 and ::1 are '
                  'kept on the terminal IP list besides the addresses given')
            )
        self.environment[_ALLOWED_IPS_ENV] = allowed_ips
        self.environment[otopicons.CoreEnv.MAIN_TRANSACTION].append(
            filetransaction.FileTransaction(
                name=self.environment[
                    oenginecons.ApacheEnv.HTTPD_CONF_OVIRT_ENGINE
                ],
                content=outil.processTemplate(
                    template=(
                        oenginecons.FileLocations.
                        HTTPD_CONF_OVIRT_ENGINE_TEMPLATE
                    ),
                    subst={
                        '@JBOSS_AJP_PORT@': self.environment[
                            oengcommcons.ConfigEnv.JBOSS_AJP_PORT
                        ],
                        '@CLIENT_CONTROL_REQUIRE_IPS@': '\n'.join(
                            '            Require ip {address}'.format(
                                address=address,
                            )
                            for address in allowed_ips
                        ),
                        '@ENGINE_SERVICE_HALTED_DIR@': (
                            oenginecons.FileLocations.HTTPD_SERVICE_HALTED_DIR
                        ),
                        '@ENGINE_SERVICE_HALTED_PAGE@': (
                            oenginecons.FileLocations.HTTPD_SERVICE_HALTED_PAGE
                        ),
                    },
                ),
                modifiedList=self.environment[
                    otopicons.CoreEnv.MODIFIED_FILES
                ],
            )
        )


# vim: expandtab tabstop=4 shiftwidth=4
