#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""CA plugin."""


import gettext
import os
import stat
import syslog

from otopi import plugin
from otopi import util

from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """CA plugin.

    Every private key the engine's PKI made - the internal CA's, the web
    server's, the engine's, the console and websocket proxies' - is destroyed
    with the engine: overwritten with zeros, then removed. No copy is kept;
    the backup of PKI configuration and keys engine-cleanup used to leave in
    the backup directory would have outlived the engine with all of them.
    """

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    @staticmethod
    def _audit(message, priority=syslog.LOG_NOTICE):
        try:
            syslog.openlog('ovirt-engine-cleanup', syslog.LOG_PID, syslog.LOG_AUTHPRIV)
            try:
                syslog.syslog(priority, message)
            finally:
                syslog.closelog()
        except Exception:
            pass

    def _destroy(self, path):
        try:
            info = os.lstat(path)
            if stat.S_ISREG(info.st_mode):
                with open(path, 'r+b', buffering=0) as stream:
                    stream.write(b'\0' * info.st_size)
                    os.fsync(stream.fileno())
            os.unlink(path)
        except OSError as e:
            self.logger.warning(
                _('Could not remove {path}: {error}').format(
                    path=path,
                    error=e,
                )
            )
            self._audit(
                'operation=key-destroy file=%s status=failure error=%s' % (path, e),
                syslog.LOG_ERR,
            )
            return False
        self._audit('operation=key-destroy file=%s status=success' % path)
        return True

    def _key_files(self):
        """Every file in the PKI's key and private directories."""
        found = []
        for directory in (
            oenginecons.FileLocations.OVIRT_ENGINE_PKIKEYSDIR,
            oenginecons.FileLocations.OVIRT_ENGINE_PKIPRIVATEDIR,
        ):
            for root, directories, files in os.walk(directory, followlinks=False):
                for name in files:
                    found.append(os.path.join(root, name))
        return sorted(found)

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        priority=plugin.Stages.PRIORITY_HIGH,
        condition=lambda self: (
            self.environment[
                oenginecons.RemoveEnv.REMOVE_ENGINE
            ] or
            'ca_pki' in [
                x.strip()
                for x in self.environment[
                    osetupcons.RemoveEnv.REMOVE_GROUPS
                ].split(',')
                if x
            ]
        ),
    )
    def _misc(self):
        # Before the files setup registered are removed (which only unlinks
        # them): every key is overwritten first. Keys setup did not register -
        # enrolled later, renamed copies - are private keys all the same.
        keys = self._key_files()
        destroyed = [path for path in keys if self._destroy(path)]
        if destroyed:
            self.logger.info(
                _('Destroyed {count} PKI private key file(s); no backup is kept').format(
                    count=len(destroyed),
                )
            )


# vim: expandtab tabstop=4 shiftwidth=4
