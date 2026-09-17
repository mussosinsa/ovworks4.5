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
    """Takes the rules engine-setup wrote back out of /etc/aide.conf.

    The file belongs to the aide package, not to this product, and everything this product put
    in it is between two markers. So the block comes out and the rest of the file stays as its
    own package left it - rather than the file being deleted, which is what happens to anything
    registered as a file setup modified, and which would take the distribution's whole AIDE
    configuration with it.
    """

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        condition=lambda self: (
            self.environment[oenginecons.RemoveEnv.REMOVE_ENGINE] and
            not self.environment[osetupcons.CoreEnv.DEVELOPER_MODE]
        ),
    )
    def _misc(self):
        if not os.path.exists(oaide.Aide.CONFIG_PATH):
            return

        with open(oaide.Aide.CONFIG_PATH, encoding='utf-8') as config_file:
            content = config_file.read()
        without = oaide.Aide.without_block(content)
        if without == content:
            return

        self.logger.info(
            _('Removing oVirt Engine rules from %s'),
            oaide.Aide.CONFIG_PATH,
        )
        self.environment[otopicons.CoreEnv.MAIN_TRANSACTION].append(
            filetransaction.FileTransaction(
                name=oaide.Aide.CONFIG_PATH,
                mode=0o600,
                owner='root',
                enforcePermissions=True,
                content=without,
            )
        )


# vim: expandtab tabstop=4 shiftwidth=4
