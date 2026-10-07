#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""AIDE configuration removal plugin."""


import gettext
import os

from otopi import constants as otopicons
from otopi import filetransaction
from otopi import plugin
from otopi import util

from ovirt_engine_setup import aide as oaide
from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """Removes the integrity verification's AIDE configuration and baseline.

    Both are the engine's own (ovirt_engine_setup/aide.py) and go with it. /etc/aide.conf is
    not: it belongs to the aide package, so from it only the block an earlier engine-setup
    wrote, between its two markers, is taken out, and the rest of the file stays as its own
    package left it.
    """

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        condition=lambda self: (
            self.environment[oenginecons.RemoveEnv.REMOVE_ENGINE] and
            not self.environment[osetupcons.CoreEnv.DEVELOPER_MODE]
        ),
    )
    def _misc(self):
        for path in (
            oaide.Aide.CONFIG_PATH,
            oaide.Aide.DATABASE,
            oaide.Aide.DATABASE_NEW,
            oaide.Aide.SEAL,
        ):
            if os.path.exists(path):
                self.logger.info(_('Removing %s'), path)
                os.unlink(path)
        try:
            os.rmdir(os.path.dirname(oaide.Aide.CONFIG_PATH))
        except OSError:
            pass

        path = oaide.Aide.LEGACY_CONFIG_PATH
        if not os.path.exists(path):
            return
        with open(path, encoding='utf-8') as config_file:
            content = config_file.read()
        without = oaide.Aide.without_legacy_block(content)
        if without == content:
            return

        self.logger.info(
            _('Removing oVirt Engine rules from %s'),
            path,
        )
        self.environment[otopicons.CoreEnv.MAIN_TRANSACTION].append(
            filetransaction.FileTransaction(
                name=path,
                mode=0o600,
                owner='root',
                enforcePermissions=True,
                content=without,
            )
        )


# vim: expandtab tabstop=4 shiftwidth=4
