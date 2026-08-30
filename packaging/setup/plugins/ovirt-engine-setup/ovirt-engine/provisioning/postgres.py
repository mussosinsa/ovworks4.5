#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""Local Postgres plugin."""


import gettext

from otopi import plugin
from otopi import util

from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons
from ovirt_engine_setup.engine_common import constants as oengcommcons
from ovirt_engine_setup.engine_common import postgres

from ovirt_setup_lib import dialog


# The setup plugin can be upgraded before ovirt-engine-setup-base.  Keep plugin
# loading compatible with that mixed-RPM window; the literal is the public
# environment key declared by newer engine-common packages.
_POSTGRES_SUPERUSER_PASSWORD = getattr(
    oengcommcons.ProvisioningEnv,
    'POSTGRES_SUPERUSER_PASSWORD',
    'OVESETUP_PROVISIONING/postgresSuperuserPassword',
)


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """Local Postgres plugin."""

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)
        self._enabled = False
        self._renamedDBResources = False
        self._provisioning = postgres.Provisioning(
            plugin=self,
            dbenvkeys=oenginecons.Const.ENGINE_DB_ENV_KEYS,
            defaults=oenginecons.Const.DEFAULT_ENGINE_DB_ENV_KEYS,
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.environment.setdefault(
            oengcommcons.ProvisioningEnv.POSTGRES_PROVISIONING_ENABLED,
            None
        )
        self.environment.setdefault(
            _POSTGRES_SUPERUSER_PASSWORD,
            None,
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_SETUP,
        after=(
            oengcommcons.Stages.DB_CONNECTION_SETUP,
        ),
        condition=lambda self: (
            not self.environment[
                osetupcons.CoreEnv.DEVELOPER_MODE
            ] and
            self.environment[
                oenginecons.EngineDBEnv.NEW_DATABASE
            ]
        ),
    )
    def _setup(self):
        self._provisioning.detectCommands()

        self._enabled = self._provisioning.supported()

    @plugin.event(
        stage=plugin.Stages.STAGE_CUSTOMIZATION,
        before=(
            oengcommcons.Stages.DIALOG_TITLES_E_DATABASE,
            oengcommcons.Stages.DB_CONNECTION_CUSTOMIZATION,
        ),
        after=(
            oengcommcons.Stages.DIALOG_TITLES_S_DATABASE,
        ),
        condition=lambda self: not self.environment[
            oenginecons.CoreEnv.ENABLE
        ],
        name=oenginecons.Stages.POSTGRES_PROVISIONING_ALLOWED,
    )
    def _customization_enable(self):
        self._enabled = False

    @plugin.event(
        stage=plugin.Stages.STAGE_CUSTOMIZATION,
        before=(
            oengcommcons.Stages.DIALOG_TITLES_E_DATABASE,
            oengcommcons.Stages.DB_CONNECTION_CUSTOMIZATION,
        ),
        after=(
            oenginecons.Stages.POSTGRES_PROVISIONING_ALLOWED,
        ),
        condition=lambda self: self._enabled,
    )
    def _customization(self):
        if self.environment[
            oengcommcons.ProvisioningEnv.POSTGRES_PROVISIONING_ENABLED
        ] is None:
            local = dialog.queryBoolean(
                dialog=self.dialog,
                name='OVESETUP_PROVISIONING_POSTGRES_LOCATION',
                note=_(
                    'Engine 데이터베이스 위치는 어디입니까? '
                    '(@VALUES@) [@DEFAULT@]: '
                ),
                prompt=True,
                true=_('Local'),
                false=_('Remote'),
                default=True,
            )
            if local:
                self.environment[oenginecons.EngineDBEnv.HOST] = 'localhost'
                self.environment[
                    oenginecons.EngineDBEnv.PORT
                ] = oenginecons.Defaults.DEFAULT_DB_PORT

                # TODO:
                # consider creating database and role
                # at engine_@RANDOM@
                self.environment[
                    oengcommcons.ProvisioningEnv.POSTGRES_PROVISIONING_ENABLED
                ] = dialog.queryBoolean(
                    dialog=self.dialog,
                    name='OVESETUP_PROVISIONING_POSTGRES_ENABLED',
                    note=_(
                        '\nSetup이 Engine 실행을 위해 로컬 postgresql 서버를 자동으로 '
                        '설정할 수 있습니다. 이 설정은 기존 애플리케이션과 충돌할 수 '
                        '있습니다.\n'
                        'Setup이 postgresql을 자동으로 설정하고 Engine 데이터베이스를 생성하도록 하시겠습니까, '
                        '아니면 수동으로 수행하시겠습니까? '
                        '(@VALUES@) [@DEFAULT@]: '
                    ),
                    prompt=True,
                    true=_('Automatic'),
                    false=_('Manual'),
                    default=True,
                )

            else:
                self.environment[
                    oengcommcons.ProvisioningEnv.POSTGRES_PROVISIONING_ENABLED
                ] = False

        self._enabled = self.environment[
            oengcommcons.ProvisioningEnv.POSTGRES_PROVISIONING_ENABLED
        ]
        if self._enabled:
            self._provisioning.applyEnvironment()
            password_key = (
                _POSTGRES_SUPERUSER_PASSWORD
            )
            while self.environment[password_key] is None:
                password = self.dialog.queryString(
                    name='OVESETUP_PROVISIONING_POSTGRES_SUPERUSER_PASSWORD',
                    note=_(
                        'PostgreSQL superuser (postgres) password: '
                    ),
                    prompt=True,
                    hidden=True,
                )
                confirmation = self.dialog.queryString(
                    name='OVESETUP_PROVISIONING_POSTGRES_SUPERUSER_PASSWORD',
                    note=_(
                        'Confirm PostgreSQL superuser password: '
                    ),
                    prompt=True,
                    hidden=True,
                )
                if password != confirmation:
                    self.logger.warning(_('Passwords do not match'))
                elif len(password) < 14:
                    self.logger.warning(
                        _('PostgreSQL superuser password must be at least 14 characters')
                    )
                else:
                    self.environment[password_key] = password

    @plugin.event(
        stage=plugin.Stages.STAGE_CUSTOMIZATION,
        priority=plugin.Stages.PRIORITY_LAST,
        condition=lambda self: (
            self.environment[
                oenginecons.EngineDBEnv.HOST
            ] == 'localhost'
        ),
    )
    def _customization_firewall(self):
        self.environment[osetupcons.NetEnv.FIREWALLD_SERVICES].extend([
            {
                'name': 'ovirt-postgres',
                'directory': 'ovirt-common'
            },
        ])

    @plugin.event(
        stage=plugin.Stages.STAGE_VALIDATION,
        condition=lambda self: self._enabled,
    )
    def _validation(self):
        password = self.environment[
            _POSTGRES_SUPERUSER_PASSWORD
        ]
        if not isinstance(password, str) or len(password) < 14:
            raise RuntimeError(
                _('PostgreSQL superuser password must be at least 14 characters')
            )
        self._provisioning.validate()

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        before=(
            oengcommcons.Stages.DB_CREDENTIALS_AVAILABLE_LATE,
            oengcommcons.Stages.DB_SCHEMA,
        ),
        after=(
            osetupcons.Stages.SYSTEM_SYSCTL_CONFIG_AVAILABLE,
        ),
        condition=lambda self: self._enabled,
    )
    def _misc(self):
        self._provisioning.provision()

    @plugin.event(
        stage=plugin.Stages.STAGE_CLOSEUP,
        before=(
            osetupcons.Stages.DIALOG_TITLES_E_SUMMARY,
        ),
        after=(
            osetupcons.Stages.DIALOG_TITLES_S_SUMMARY,
        ),
        condition=lambda self: self._enabled,
    )
    def _closeup_set_postgres_superuser_password(self):
        set_password = getattr(
            self._provisioning,
            'setPostgresSuperuserPassword',
            None,
        )
        if not callable(set_password):
            # During a rolling RPM update the setup plugin can be loaded with
            # an older engine-common package.  That implementation applies the
            # password from provision(), so there is no closeup action to run.
            self.logger.debug(
                'PostgreSQL provisioning does not support deferred password '
                'finalization; it was handled during provisioning'
            )
            return
        self.logger.info(_('Setting PostgreSQL superuser password'))
        set_password()

    @plugin.event(
        stage=plugin.Stages.STAGE_CLOSEUP,
        before=(
            osetupcons.Stages.DIALOG_TITLES_E_SUMMARY,
        ),
        after=(
            osetupcons.Stages.DIALOG_TITLES_S_SUMMARY,
        ),
        condition=lambda self: self._provisioning.databaseRenamed,
    )
    def _closeup(self):
        self.dialog.note(
            text=_(
                'Engine database resources:\n'
                '    Database name:      {database}\n'
                '    Database user name: {user}\n'
            ).format(
                database=self.environment[
                    oenginecons.EngineDBEnv.DATABASE
                ],
                user=self.environment[
                    oenginecons.EngineDBEnv.USER
                ],
            )
        )


# vim: expandtab tabstop=4 shiftwidth=4
