#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""Put the SCRAM runtime where the Data Warehouse ETL can load it."""


import gettext
import os

from otopi import plugin
from otopi import util

from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """Supplies the Data Warehouse ETL with the SCRAM runtime.

    Setup makes the database speak SCRAM-SHA-256. Everything that then connects
    to it needs the ONGRES libraries the PostgreSQL JDBC driver calls to answer
    the challenge, and the engine has them: they are bundled in its
    org.postgresql JBoss module, which is why the engine itself, the notifier
    and ovirt-aaa-jdbc-tool all authenticate. Those three reach that module
    because they run under JBoss modules.

    The Data Warehouse ETL does not. It is a plain JVM started by
    ovirt-engine-dwhd with a classpath of its own, and that classpath carries
    the JDBC driver without the libraries the driver needs. So the moment
    setup turns SCRAM on, the ETL stops being able to log in - not visibly, but
    with NoClassDefFoundError inside the driver, a service that exits 1 and is
    restarted forever, and a dashboard that reads zero because no sample is
    ever collected. Nothing says the database is refusing it.

    The ETL belongs to another package, so this cannot be fixed where it is
    used; it is fixed where the cause is, beside the code that turns SCRAM on.
    Links rather than copies, so that an engine update carries a corrected
    library across without this having to run again.
    """

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        condition=lambda self: (
            self.environment[oenginecons.CoreEnv.ENABLE] and
            not self.environment[
                osetupcons.CoreEnv.DEVELOPER_MODE
            ]
        ),
    )
    def _misc(self):
        target_dirs = self._dwh_java_lib_dirs()
        if not target_dirs:
            self.logger.debug(
                'Data Warehouse ETL is not installed on this host; '
                'not supplying the SCRAM runtime'
            )
            return

        source_dir = oenginecons.FileLocations.OVIRT_ENGINE_POSTGRES_MODULE_DIR
        missing = [
            jar for jar in oenginecons.FileLocations.SCRAM_RUNTIME_JARS
            if not os.path.exists(os.path.join(source_dir, jar))
        ]
        if missing:
            # Not survivable and not worth continuing past. The same libraries
            # are what the engine itself authenticates with, so an installation
            # missing them has more wrong with it than the Data Warehouse.
            raise RuntimeError(
                _(
                    'The SCRAM runtime the PostgreSQL driver needs is missing '
                    'from {directory}: {jars}. The database is configured for '
                    'scram-sha-256, so neither the engine nor the Data '
                    'Warehouse can authenticate without it.'
                ).format(
                    directory=source_dir,
                    jars=', '.join(missing),
                )
            )

        for target_dir in target_dirs:
            self._link_runtime(source_dir, target_dir)

    def _dwh_java_lib_dirs(self):
        """@return the ETL's JAR directories present on this host, or empty"""
        return [
            directory
            for directory in oenginecons.FileLocations.DWH_JAVA_LIB_DIRS
            if os.path.exists(
                os.path.join(
                    directory,
                    oenginecons.FileLocations.DWH_ETL_JAR,
                )
            )
        ]

    def _link_runtime(self, source_dir, target_dir):
        """Links the four libraries into one of the ETL's JAR directories.

        Replaced rather than skipped when a link is already there, so that
        running engine-setup again repairs a link left pointing at a library
        that has since moved.
        """
        for jar in oenginecons.FileLocations.SCRAM_RUNTIME_JARS:
            source = os.path.join(source_dir, jar)
            target = os.path.join(
                target_dir,
                '{prefix}{jar}'.format(
                    prefix=oenginecons.FileLocations.SCRAM_RUNTIME_LINK_PREFIX,
                    jar=jar,
                ),
            )
            try:
                if os.path.islink(target) or os.path.exists(target):
                    os.unlink(target)
                os.symlink(source, target)
            except OSError as e:
                # Raised rather than warned. Carrying on leaves a Data
                # Warehouse that cannot log in and says so nowhere an
                # administrator looks - which is the whole reason this exists.
                raise RuntimeError(
                    _(
                        'Could not give the Data Warehouse the SCRAM runtime '
                        'it needs ({target}): {error}. Without it '
                        'ovirt-engine-dwhd cannot authenticate against a '
                        'scram-sha-256 database and collects no statistics.'
                    ).format(target=target, error=e)
                )
        self.logger.info(
            _(
                'Supplied the Data Warehouse with the SCRAM runtime: '
                '{directory}'
            ).format(directory=target_dir)
        )


# vim: expandtab tabstop=4 shiftwidth=4
