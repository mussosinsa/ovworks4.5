#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""AAA-JDBC extension admin user setup plugin."""

import datetime
import gettext
import os

from otopi import constants as otopicons
from otopi import filetransaction
from otopi import plugin
from otopi import util

from ovirt_engine import util as outil

from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons
from ovirt_engine_setup.engine import vdcoption
from ovirt_engine_setup.engine_common import constants as oengcommcons
from ovirt_engine_setup.engine_common import database


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """AAA-JDBC extension admin user setup plugin."""

    PACKAGE_NAME = 'ovirt-engine-extension-aaa-jdbc'

    AAA_JDBC_SETUP_ADMIN_USER = 'osetup.aaa_jdbc.config.setup.admin.user'

    AAA_JDBC_AUTHZ_TYPE = 'ovirt-engine-extension-aaa-jdbc'

    _AAA_JDBC_SCHEMA = 'aaa_jdbc'

    # How long aaa-jdbc holds an account after too many failed passwords, and where the engine
    # keeps the same number for itself.
    #
    # There are two locks on one login. The engine's own, which it applies from the SSO path,
    # and this one, which aaa-jdbc applies inside the authentication it performs. An account is
    # usable again only when both have lifted, so aaa-jdbc holding a lock for its default hour
    # makes the engine's five minutes mean nothing: the account stays locked for the hour and
    # the engine's audit log says it was released.
    _AAA_JDBC_LOCK_MINUTES_SETTING = 'LOCK_MINUTES'
    _ENGINE_LOCK_MINUTES_OPTION = 'ENGINE_SSO_ADMIN_LOCK_MINUTES'
    _DEFAULT_LOCK_MINUTES = 5

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    def _userExists(self, toolArgs, toolEnv, name):
        rc, stdout, stderr = self.execute(
            args=toolArgs + (
                'query',
                '--what=user',
                '--pattern=name=%s' % name,
            ),
            envAppend=toolEnv,
        )
        return (
            rc == 0 and
            name in ' '.join(stdout)
        )

    def _createUser(self, toolArgs, toolEnv, name, email, id):
        self.execute(
            args=toolArgs + (
                'user',
                'add',
                name,
                '--attribute=firstName=%s' % name,
                '--attribute=email=%s' % email,
            ) + (
                (
                    '--id=%s' % id,
                ) if id is not None else ()
            ),
            envAppend=toolEnv,
        )

    def _getUserId(self, toolArgs, toolEnv, name):
        rc, stdout, stderr = self.execute(
            args=toolArgs + (
                'user',
                'show',
                name,
                '--attribute=id',
            ),
            envAppend=toolEnv,
        )
        return stdout[0]

    def _getUserEmail(self, toolArgs, toolEnv, name):
        rc, stdout, stderr = self.execute(
            args=toolArgs + (
                'user',
                'show',
                name,
                '--attribute=email',
            ),
            envAppend=toolEnv,
        )
        return stdout[0]

    def _setUserEmail(self, toolArgs, toolEnv, name, email):
        rc, stdout, stderr = self.execute(
            args=toolArgs + (
                'user',
                'edit',
                name,
                '--attribute=email=%s' % email,
            ),
            envAppend=toolEnv,
        )

    def _setupSchema(self):
        self.logger.info(
            _("Creating/refreshing Engine 'internal' domain database schema")
        )
        args = [
            oenginecons.FileLocations.AAA_JDBC_DB_SCHMA_TOOL,
            '-s', self.environment[oenginecons.EngineDBEnv.HOST],
            '-p', str(self.environment[oenginecons.EngineDBEnv.PORT]),
            '-u', self.environment[oenginecons.EngineDBEnv.USER],
            '-d', self.environment[oenginecons.EngineDBEnv.DATABASE],
            '-e', self._AAA_JDBC_SCHEMA,
            '-l', self.environment[otopicons.CoreEnv.LOG_FILE_NAME],
            '-c', 'apply',
        ]
        if self.environment[
            osetupcons.CoreEnv.DEVELOPER_MODE
        ]:
            if not os.path.exists(
                oenginecons.FileLocations.OVIRT_ENGINE_DB_MD5_DIR
            ):
                os.makedirs(
                    oenginecons.FileLocations.OVIRT_ENGINE_DB_MD5_DIR
                )
            args.extend(
                [
                    '-m',
                    os.path.join(
                        oenginecons.FileLocations.OVIRT_ENGINE_DB_MD5_DIR,
                        '%s-%s-aaa-jdbc.scripts.md5' % (
                            self.environment[
                                oenginecons.EngineDBEnv.HOST
                            ],
                            self.environment[
                                oenginecons.EngineDBEnv.DATABASE
                            ],
                        ),
                        ),
                ]
            )
        self.execute(
            args=args,
            envAppend={
                'DBFUNC_DB_PGPASSFILE': self.environment[
                    oenginecons.EngineDBEnv.PGPASS_FILE
                ]
            },
        )

    def _getDatasourceConfigContent(self):
        return (
            'config.datasource.jdbcurl={jdbcUrl}\n'
            'config.datasource.dbuser={user}\n'
            'config.datasource.dbpassword={password}\n'
            'config.datasource.jdbcdriver=org.postgresql.Driver\n'
            'config.datasource.schemaname={schemaName}\n'
        ).format(
            jdbcUrl=database.OvirtUtils(
                plugin=self,
                dbenvkeys=oenginecons.Const.ENGINE_DB_ENV_KEYS,
            ).getJdbcUrl(),
            user=self.environment[oenginecons.EngineDBEnv.USER],
            password=outil.escape(
                self.environment[oenginecons.EngineDBEnv.PASSWORD],
                '"\\$',
            ),
            schemaName=self._AAA_JDBC_SCHEMA
        )

    def _setupAuth(self):
        datasourceConfig = self._getDatasourceConfigContent()
        self.environment[otopicons.CoreEnv.MAIN_TRANSACTION].append(
            filetransaction.FileTransaction(
                name=oenginecons.FileLocations.AAA_JDBC_CONFIG_DB,
                mode=0o600,
                owner=self.environment[osetupcons.SystemEnv.USER_ENGINE],
                enforcePermissions=True,
                content=datasourceConfig,
                visibleButUnsafe=True,
                modifiedList=self.environment[
                    otopicons.CoreEnv.MODIFIED_FILES
                ],
            )
        )

        profile = self.environment[
            oenginecons.ConfigEnv.ADMIN_USER
        ].rsplit('@', 1)[1]

        self.environment[otopicons.CoreEnv.MAIN_TRANSACTION].append(
            filetransaction.FileTransaction(
                name=(
                    os.path.join(
                        oenginecons.FileLocations.OVIRT_ENGINE_EXTENSIONS_DIR,
                        '%s-authn.properties' % profile
                    )
                ),
                mode=0o600,
                owner=self.environment[osetupcons.SystemEnv.USER_ENGINE],
                enforcePermissions=True,
                content=(
                    'ovirt.engine.extension.name = internal-authn\n'
                    'ovirt.engine.extension.bindings.method = jbossmodule\n'

                    'ovirt.engine.extension.binding.jbossmodule.module = '
                    'org.ovirt.engine.extension.aaa.jdbc\n'

                    'ovirt.engine.extension.binding.jbossmodule.class = '
                    'org.ovirt.engine.extension.aaa.jdbc.binding.api.'
                    'AuthnExtension\n'

                    'ovirt.engine.extension.provides = '
                    'org.ovirt.engine.api.extensions.aaa.Authn\n'

                    'ovirt.engine.aaa.authn.profile.name = {profile}\n'
                    'ovirt.engine.aaa.authn.authz.plugin = {authzName}\n'
                    '{datasourceConfig}'
                ).format(
                    profile=profile,
                    authzName=self.environment[
                        oenginecons.ConfigEnv.ADMIN_USER_AUTHZ_NAME
                    ],
                    datasourceConfig=datasourceConfig,
                ),
                visibleButUnsafe=True,
                modifiedList=self.environment[
                    otopicons.CoreEnv.MODIFIED_FILES
                ],
            )
        )
        self.environment[otopicons.CoreEnv.MAIN_TRANSACTION].append(
            filetransaction.FileTransaction(
                name=(
                    os.path.join(
                        oenginecons.FileLocations.OVIRT_ENGINE_EXTENSIONS_DIR,
                        '%s-authz.properties' % profile
                    )
                ),
                mode=0o600,
                owner=self.environment[osetupcons.SystemEnv.USER_ENGINE],
                enforcePermissions=True,
                content=(
                    'ovirt.engine.extension.name = {authzName}\n'
                    'ovirt.engine.extension.bindings.method = jbossmodule\n'

                    'ovirt.engine.extension.binding.jbossmodule.module = '
                    'org.ovirt.engine.extension.aaa.jdbc\n'

                    'ovirt.engine.extension.binding.jbossmodule.class = '
                    'org.ovirt.engine.extension.aaa.jdbc.binding.api.'
                    'AuthzExtension\n'

                    'ovirt.engine.extension.provides = '
                    'org.ovirt.engine.api.extensions.aaa.Authz\n'

                    '{datasourceConfig}'
                ).format(
                    authzName=self.environment[
                        oenginecons.ConfigEnv.ADMIN_USER_AUTHZ_NAME
                    ],
                    datasourceConfig=datasourceConfig,
                ),
                visibleButUnsafe=True,
                modifiedList=self.environment[
                    otopicons.CoreEnv.MODIFIED_FILES
                ],
            )
        )

    def _setupAdminUser(self):
        toolArgs = (
            oenginecons.FileLocations.AAA_JDBC_TOOL,
            '--db-config=%s' % oenginecons.FileLocations.AAA_JDBC_CONFIG_DB,
        )

        toolEnv = {
            'OVIRT_ENGINE_JAVA_HOME_FORCE': '1',
            'OVIRT_ENGINE_JAVA_HOME': self.environment[
                oengcommcons.ConfigEnv.JAVA_HOME
            ],
            'OVIRT_JBOSS_HOME': self.environment[
                oengcommcons.ConfigEnv.JBOSS_HOME
            ],
        }

        adminUser = self.environment[
            oenginecons.ConfigEnv.ADMIN_USER
        ].rsplit('@', 1)[0]

        # Should this be configurable? User can change it later.
        adminEmail = 'admin@localhost'

        if not self._userExists(
            toolArgs=toolArgs,
            toolEnv=toolEnv,
            name=adminUser,
        ):
            self._createUser(
                toolArgs=toolArgs,
                toolEnv=toolEnv,
                name=adminUser,
                email=adminEmail,
                id=self.environment[oenginecons.ConfigEnv.ADMIN_USER_ID],
            )

            if self.environment[
                oenginecons.ConfigEnv.ADMIN_USER_ID
            ] is None:
                self.environment[
                    oenginecons.ConfigEnv.ADMIN_USER_ID
                ] = self._getUserId(
                    toolArgs=toolArgs,
                    toolEnv=toolEnv,
                    name=adminUser,
                )
        elif '@' not in self._getUserEmail(
            toolArgs=toolArgs,
            toolEnv=toolEnv,
            name=adminUser,
        ):
            self._setUserEmail(
                toolArgs=toolArgs,
                toolEnv=toolEnv,
                name=adminUser,
                email=adminEmail,
            )

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.environment.setdefault(
            oenginecons.RPMDistroEnv.ENGINE_AAA_JDBC_PACKAGE,
            self.PACKAGE_NAME
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_CUSTOMIZATION,
        after=(
            oenginecons.Stages.CORE_ENABLE,
        ),
        before=(
            osetupcons.Stages.DIALOG_TITLES_E_PRODUCT_OPTIONS,
        ),
        condition=lambda self: (
            self.environment[oenginecons.CoreEnv.ENABLE] and
            os.path.exists(oenginecons.FileLocations.AAA_JDBC_DB_SCHMA_TOOL)
        ),
    )
    def _customization(self):
        self.environment[
            oenginecons.ConfigEnv.ADMIN_USER_AUTHZ_TYPE
        ] = self.AAA_JDBC_AUTHZ_TYPE

    @plugin.event(
        stage=plugin.Stages.STAGE_CUSTOMIZATION,
        before=(
            osetupcons.Stages.DISTRO_RPM_PACKAGE_UPDATE_CHECK,
        ),
    )
    def _version_lock_customization(self):
        self.environment[
            osetupcons.RPMDistroEnv.VERSION_LOCK_FILTER
        ].append(
            self.environment[
                oenginecons.RPMDistroEnv.ENGINE_AAA_JDBC_PACKAGE
            ]
        )
        self.environment[
            osetupcons.RPMDistroEnv.VERSION_LOCK_APPLY
        ].append(
            self.environment[
                oenginecons.RPMDistroEnv.ENGINE_AAA_JDBC_PACKAGE
            ]
        )
        self.environment[
            osetupcons.RPMDistroEnv.PACKAGES_UPGRADE_LIST
        ].append(
            {
                'packages': [
                    self.environment[
                        oenginecons.RPMDistroEnv.ENGINE_AAA_JDBC_PACKAGE
                    ]
                ]
            },
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        name=AAA_JDBC_SETUP_ADMIN_USER,
        after=(
            oengcommcons.Stages.DB_SCHEMA,
            oengcommcons.Stages.DB_CONNECTION_AVAILABLE,
            oenginecons.Stages.CONFIG_EXTENSIONS_UPGRADE,
        ),
        before=(
            oenginecons.Stages.CONFIG_AAA_ADMIN_USER_SETUP,
        ),
        condition=lambda self: self.environment[
            oenginecons.ConfigEnv.ADMIN_USER_AUTHZ_TYPE
        ] == self.AAA_JDBC_AUTHZ_TYPE,
    )
    def _misc(self):
        # TODO: if we knew that aaa-jdbc package was upgraded by engine-setup
        # TODO: we could display summary note that custom profiles have to be
        # TODO: upgraded manually
        self._setupSchema()
        self._setupAuth()
        self._setupAdminUser()

    def _engineLockMinutes(self):
        """How long the engine holds a locked account, which aaa-jdbc is made to match.

        Read from the engine's own configuration rather than asked for again, so that an
        administrator who changes it with engine-config and runs engine-setup gets the two
        halves of the lock moving together.
        """
        try:
            configured = vdcoption.VdcOption(
                statement=database.Statement(
                    dbenvkeys=oenginecons.Const.ENGINE_DB_ENV_KEYS,
                    environment=self.environment,
                ),
            ).getVdcOption(
                self._ENGINE_LOCK_MINUTES_OPTION,
                ownConnection=True,
            )
        except RuntimeError:
            # Not in the database yet. A fresh install before the option is inserted, or an
            # engine old enough not to have it.
            return self._DEFAULT_LOCK_MINUTES

        try:
            minutes = int(configured)
        except (TypeError, ValueError):
            minutes = 0
        if minutes <= 0:
            self.logger.warning(
                _(
                    '{option} is {value}, which is not a number of minutes. '
                    'Using {default} for the aaa-jdbc lock instead.'
                ).format(
                    option=self._ENGINE_LOCK_MINUTES_OPTION,
                    value=configured,
                    default=self._DEFAULT_LOCK_MINUTES,
                )
            )
            return self._DEFAULT_LOCK_MINUTES
        return minutes

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        after=(
            AAA_JDBC_SETUP_ADMIN_USER,
            oengcommcons.Stages.DB_SCHEMA,
        ),
        condition=lambda self: not self.environment[
            osetupcons.CoreEnv.DEVELOPER_MODE
        ],
    )
    def _setupLockMinutes(self):
        if not os.path.exists(oenginecons.FileLocations.AAA_JDBC_CONFIG_DB):
            # No internal provider on this installation, so it has no lock to align.
            return

        minutes = self._engineLockMinutes()
        self.logger.info(
            _(
                'Setting the aaa-jdbc account lock to {minutes} minutes, to match {option}'
            ).format(
                minutes=minutes,
                option=self._ENGINE_LOCK_MINUTES_OPTION,
            )
        )
        # Applied on every run rather than only when it is unset. The setting is not this
        # product's to hold a value of its own: it exists here to be the engine's number, and a
        # run of engine-setup is when the two are brought back together.
        self.execute(
            args=(
                oenginecons.FileLocations.AAA_JDBC_TOOL,
                '--db-config=%s' % (
                    oenginecons.FileLocations.AAA_JDBC_CONFIG_DB
                ),
                'settings',
                'set',
                '--name=%s' % self._AAA_JDBC_LOCK_MINUTES_SETTING,
                '--value=%s' % minutes,
            ),
            envAppend={
                'OVIRT_ENGINE_JAVA_HOME_FORCE': '1',
                'OVIRT_ENGINE_JAVA_HOME': self.environment[
                    oengcommcons.ConfigEnv.JAVA_HOME
                ],
                'OVIRT_JBOSS_HOME': self.environment[
                    oengcommcons.ConfigEnv.JBOSS_HOME
                ],
            },
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        after=(
            AAA_JDBC_SETUP_ADMIN_USER,
        ),
        condition=lambda self: (
            self.environment[
                oenginecons.ConfigEnv.ADMIN_USER_AUTHZ_TYPE
            ] == self.AAA_JDBC_AUTHZ_TYPE and
            self.environment[
                oenginecons.ConfigEnv.ADMIN_PASSWORD
            ] is not None
        ),
    )
    def _setupAdminPassword(self):
        adminUser = self.environment[
            oenginecons.ConfigEnv.ADMIN_USER
        ].rsplit('@', 1)[0]

        # Do not apply the configurable regular-user policy to the bootstrap
        # administrator. Its setup password is always temporary.
        forceChange = True

        self.logger.info(
            _(
                'Setting a password for internal user {admin}'
            ).format(
                admin=adminUser,
            )
        )
        if forceChange:
            self.logger.info(
                _(
                    'The password is stored as already expired, {admin} has '
                    'to change it on the first login'
                ).format(
                    admin=adminUser,
                )
            )

        # Truncating the reset time to seconds makes the password expire
        # immediately after setup, since the login that follows is later than
        # the whole second this lands on.
        #
        # The claim this comment used to carry - that a validity predating the
        # account's own valid-from makes aaa-jdbc report an extension failure
        # rather than expired credentials - does not hold for the aaa-jdbc this
        # ships with: the two timestamps are written independently and never
        # compared, and valid-from is read in one place, only against the login
        # time. Nothing here depends on the ordering, so do not add a margin
        # back on the strength of it. Keeping the reset time at "now" is still
        # right: it is the smallest step into the past that expires it.
        if forceChange:
            passwordValidTo = datetime.datetime.utcnow()
        else:
            passwordValidTo = datetime.datetime.utcnow() + \
                datetime.timedelta(days=73000)

        self.execute(
            args=(
                oenginecons.FileLocations.AAA_JDBC_TOOL,
                '--db-config=%s' % (
                    oenginecons.FileLocations.AAA_JDBC_CONFIG_DB
                ),

                'user',
                'password-reset',
                adminUser,
                '--password=env:pass',

                # we need to skip password validity checks when upgrading
                # from legacy internal provider
                '--force',

                '--password-valid-to=%sZ' % (
                    passwordValidTo.replace(
                        microsecond=0,
                    ).isoformat(' ')
                ),
            ),
            envAppend={
                'OVIRT_ENGINE_JAVA_HOME_FORCE': '1',
                'OVIRT_ENGINE_JAVA_HOME': self.environment[
                    oengcommcons.ConfigEnv.JAVA_HOME
                ],
                'OVIRT_JBOSS_HOME': self.environment[
                    oengcommcons.ConfigEnv.JBOSS_HOME
                ],
                'pass': self.environment[
                    oenginecons.ConfigEnv.ADMIN_PASSWORD
                ],
            },
        )


# vim: expandtab tabstop=4 shiftwidth=4
