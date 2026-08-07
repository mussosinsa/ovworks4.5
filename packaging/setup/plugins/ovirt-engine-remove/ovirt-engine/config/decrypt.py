#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""Engine-remove config decryption plugin."""


import gettext
import os

from otopi import plugin
from otopi import util

from ovirt_engine_setup.engine import constants as oenginecons


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """Decrypt selected config files before remove reads them."""

    _ENCRYPTOR_PATH = '/usr/share/ovirt-engine/encryptor/encryptor.py'
    _DECRYPT_ALLOWED_FILES = (
        oenginecons.FileLocations.AAA_JDBC_CONFIG_DB,
        oenginecons.FileLocations.OVIRT_ENGINE_SERVICE_CONFIG_DATABASE,
        oenginecons.FileLocations.OVIRT_ENGINE_SERVICE_CONFIG_DWH_DATABASE,
    )

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    def _decrypt_config_file(self, config_path):
        if not os.path.exists(config_path):
            return

        if not os.path.exists(self._ENCRYPTOR_PATH):
            self.logger.debug(
                'Encryptor tool not found at %s, skipping decryption of %s',
                self._ENCRYPTOR_PATH,
                config_path,
            )
            return

        try:
            with open(config_path, 'rb') as config_file:
                original_content = config_file.read()
        except Exception:
            self.logger.warning(
                'Cannot read %s before decryption attempt',
                config_path,
                exc_info=True,
            )
            return

        python = self.command.get('python3', optional=True)
        if python is None:
            python = '/usr/bin/python3'

        def _restore_original_content():
            with open(config_path, 'wb') as config_file:
                config_file.write(original_content)

        for args in (
            ('--decrypt', config_path),
            ('-d', config_path),
        ):
            rc, stdout, stderr = self.execute(
                (python, self._ENCRYPTOR_PATH) + args,
                raiseOnError=False,
            )
            if rc == 0:
                self.logger.debug(
                    'Decrypted config %s using %s %s',
                    config_path,
                    self._ENCRYPTOR_PATH,
                    ' '.join(args),
                )
                return

            self.logger.debug(
                'Decrypt attempt failed for %s using %s %s (rc=%s), restoring original content',
                config_path,
                self._ENCRYPTOR_PATH,
                ' '.join(args),
                rc,
            )
            _restore_original_content()

        self.logger.warning(
            'Failed to decrypt %s with %s; using original content',
            config_path,
            self._ENCRYPTOR_PATH,
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.command.detect('python3')
        for config_path in self._DECRYPT_ALLOWED_FILES:
            self._decrypt_config_file(config_path)
