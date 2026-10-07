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

from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


# Shared with config/misc.py, which must not destroy the DEK while a file
# decrypted here is still on disk and could be put back under it.
DECRYPTED_FILES_ENV = 'OVESETUP_REMOVE_ENCRYPTOR/decryptedFiles'
REENCRYPTED_EVENT = 'osetup.remove.encryptor.reencrypted'

_ENCRYPTED_MAGICS = (b'OVENC002', b'OVENC001', b'OVVLT001')


@util.export
class Plugin(plugin.PluginBase):
    """Decrypt selected config files before remove reads them.

    They are decrypted in place so that the files setup registered for removal
    match again and are removed with the rest. A file decrypted here is never
    left as plain text: what is still on disk when engine-cleanup ends - the
    engine was not removed, a component that stays installed owns it, or the
    run stopped half way - is encrypted again under the installation's DEK.
    """

    _ENCRYPTOR_PATH = '/usr/share/ovirt-engine/encryptor/encryptor.py'
    _KEK_AGENT_PATH = '/usr/share/ovirt-engine/encryptor/kek_agent.py'
    _ENCRYPTOR_CONFIG_PATH = '/etc/ovirt-engine/encryptor/config.json'
    _DECRYPT_ALLOWED_FILES = (
        oenginecons.FileLocations.AAA_JDBC_CONFIG_DB,
        oenginecons.FileLocations.OVIRT_ENGINE_SERVICE_CONFIG_DATABASE,
        oenginecons.FileLocations.OVIRT_ENGINE_SERVICE_CONFIG_DWH_DATABASE,
    )

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    def _python(self):
        python = self.command.get('python3', optional=True)
        return python or '/usr/bin/python3'

    @staticmethod
    def _magic(path):
        try:
            with open(path, 'rb') as stream:
                return stream.read(8)
        except OSError:
            return b''

    def _require_kek_passphrase(self, encrypted):
        """Stops before anything is changed when the passphrase is not held.

        Without it nothing can be decrypted: the files setup registered would
        not match and be kept, the database could not be reached to be
        cleaned, and the DEK destroyed at the end would leave them unreadable
        for good.
        """
        if not any(self._magic(path) == b'OVENC002' for path in encrypted):
            return
        if not os.path.exists(self._KEK_AGENT_PATH):
            raise RuntimeError(
                _('KEK agent tool not found: {path}').format(
                    path=self._KEK_AGENT_PATH,
                )
            )
        rc, stdout, stderr = self.execute(
            (
                self._python(), self._KEK_AGENT_PATH,
                '--status', '--config', self._ENCRYPTOR_CONFIG_PATH,
            ),
            raiseOnError=False,
        )
        if rc != 0:
            raise RuntimeError(
                _(
                    'The KEK passphrase is not loaded in memory, so the '
                    'encrypted configuration files cannot be decrypted. Run '
                    '{tool} --unlock and then engine-cleanup again'
                ).format(tool=self._KEK_AGENT_PATH)
            )

    def _decrypt_config_file(self, config_path):
        if self._magic(config_path) not in _ENCRYPTED_MAGICS:
            return False
        if not os.path.exists(self._ENCRYPTOR_PATH):
            raise RuntimeError(
                _('Encryptor tool not found: {path}').format(
                    path=self._ENCRYPTOR_PATH,
                )
            )
        rc, stdout, stderr = self.execute(
            (
                self._python(), self._ENCRYPTOR_PATH,
                '--decrypt', '--deny-legacy-cbc',
                '--config', self._ENCRYPTOR_CONFIG_PATH,
                config_path,
            ),
            raiseOnError=False,
        )
        if rc != 0 or self._magic(config_path) in _ENCRYPTED_MAGICS:
            # Not passed over with a warning any more: carrying on removed the
            # DEK at the end and left this file unreadable for good.
            raise RuntimeError(
                _('Failed to decrypt {path}: {error}').format(
                    path=config_path,
                    error='\n'.join(stderr or stdout or []).strip(),
                )
            )
        self.logger.debug('Decrypted config %s for removal', config_path)
        return True

    def _reencrypt_leftovers(self):
        """Puts every file decrypted here and still on disk back under the DEK."""
        left = []
        for path in self.environment[DECRYPTED_FILES_ENV]:
            if not os.path.isfile(path):
                continue
            if self._magic(path) in _ENCRYPTED_MAGICS:
                continue
            rc, stdout, stderr = self.execute(
                (
                    self._python(), self._ENCRYPTOR_PATH,
                    '--encrypt', '--config', self._ENCRYPTOR_CONFIG_PATH,
                    path,
                ),
                raiseOnError=False,
            )
            if rc == 0 and self._magic(path) in _ENCRYPTED_MAGICS:
                self.logger.info(
                    _('Encrypted again (kept on this host): {path}').format(
                        path=path,
                    )
                )
            else:
                left.append(path)
                self.logger.error(
                    _(
                        'Could not encrypt {path} again; it holds a database '
                        'password in plain text: {error}'
                    ).format(
                        path=path,
                        error='\n'.join(stderr or stdout or []).strip(),
                    )
                )
        return left

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.command.detect('python3')
        self.environment[DECRYPTED_FILES_ENV] = []
        encrypted = [
            path for path in self._DECRYPT_ALLOWED_FILES
            if self._magic(path) in _ENCRYPTED_MAGICS
        ]
        if not encrypted:
            return
        self._require_kek_passphrase(encrypted)
        for config_path in encrypted:
            if self._decrypt_config_file(config_path):
                self.environment[DECRYPTED_FILES_ENV].append(config_path)

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        priority=plugin.Stages.PRIORITY_HIGH,
    )
    def _misc(self):
        # Decrypted for removal and about to be removed, which only unlinks:
        # the database passwords in them are overwritten first.
        to_remove = self.environment.get(
            osetupcons.RemoveEnv.FILES_TO_REMOVE
        ) or set()
        for path in self.environment[DECRYPTED_FILES_ENV]:
            if path not in to_remove or not os.path.isfile(path):
                continue
            try:
                size = os.path.getsize(path)
                with open(path, 'r+b', buffering=0) as stream:
                    stream.write(b'\0' * size)
                    os.fsync(stream.fileno())
            except OSError as e:
                self.logger.warning(
                    _('Could not overwrite {path} before removal: {error}').format(
                        path=path,
                        error=e,
                    )
                )

    @plugin.event(
        stage=plugin.Stages.STAGE_CLOSEUP,
        name=REENCRYPTED_EVENT,
    )
    def _closeup(self):
        # Before config/misc.py destroys the DEK: a file a component that
        # stays installed still needs (the data warehouse's) goes back under it.
        self._reencrypt_leftovers()

    @plugin.event(
        stage=plugin.Stages.STAGE_CLEANUP,
    )
    def _cleanup(self):
        # The engine was not removed, or engine-cleanup stopped half way:
        # nothing decrypted at the start may stay in plain text.
        self._reencrypt_leftovers()


# vim: expandtab tabstop=4 shiftwidth=4
