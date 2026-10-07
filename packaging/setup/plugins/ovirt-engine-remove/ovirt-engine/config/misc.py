#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""Engine-remove plugin."""


import gettext
import importlib.util
import json
import os
import stat
import syslog
import tempfile

from otopi import plugin
from otopi import util

from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons

from ovirt_setup_lib import dialog

from . import decrypt as remove_decrypt


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """Engine-remove plugin."""
    _ENCRYPTOR_CONFIG_PATH = '/etc/ovirt-engine/encryptor/config.json'
    _ENCRYPTOR_PRIVATE_KEY_PATH = '/etc/ovirt-engine/encryptor/private_pkcs8.der'
    _ENCRYPTOR_CONFIG = {
        "encrypt_flag": "NO",
        "watch_path": [
            "/etc/ovirt-engine",
            "/etc/ovirt-engine-dwh",
        ],
        "allowed_files": [
            "10-setup-database.conf",
            "10-setup-dwh-database.conf",
            "internal.properties",
        ],
        "legacy_cbc": {
            "enabled": False,
        },
        # The next engine-setup asks for a new KEK passphrase and holds it in
        # memory; no passphrase file and no Vault.
        "kek_agent": {
            "enabled": True,
            "socket": "/run/ovirt-engine-kek/agent.sock",
        },
    }
    # Secrets of the removed installation. Nothing is encrypted with them any
    # more: the configuration files were decrypted when engine-cleanup started.
    _ENCRYPTOR_STALE_SECRETS = (
        '/etc/ovirt-engine/encryptor/passphrase',
        '/etc/ovirt-engine/encryptor/vault-token',
        # The installation's DEK, wrapped by the KEK.
        '/etc/ovirt-engine/encryptor/dek.enc',
    )
    _KEK_AGENT_SERVICE = 'ovirt-engine-kek-agent.service'
    _ENCRYPTOR_TOOL_PATH = '/usr/share/ovirt-engine/encryptor/encryptor.py'
    _DEK_PATH = '/etc/ovirt-engine/encryptor/dek.enc'

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    def _write_encryptor_config(self):
        config_dir = os.path.dirname(self._ENCRYPTOR_CONFIG_PATH)
        if config_dir and not os.path.isdir(config_dir):
            os.makedirs(config_dir, mode=0o700)
        descriptor, temporary_path = tempfile.mkstemp(
            prefix='.config.json.',
            dir=config_dir,
            text=True,
        )
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as config_file:
                json.dump(self._ENCRYPTOR_CONFIG, config_file, indent=2)
                config_file.write('\n')
                config_file.flush()
                os.fsync(config_file.fileno())
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, self._ENCRYPTOR_CONFIG_PATH)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)

    @staticmethod
    def _audit(message, priority=syslog.LOG_NOTICE):
        """What became of a key, where it outlives the engine: the engine's
        own event list is being removed with it."""
        try:
            syslog.openlog('ovirt-engine-cleanup', syslog.LOG_PID, syslog.LOG_AUTHPRIV)
            try:
                syslog.syslog(priority, message)
            finally:
                syslog.closelog()
        except Exception:
            pass

    def _destroy(self, path):
        """Overwrites a key file with zeros, then removes it. @return removed"""
        try:
            info = os.lstat(path)
        except OSError:
            return False
        try:
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

    def _dek_still_needed(self):
        """Files the DEK must stay for: still encrypted under it (a component
        that stays installed, such as the data warehouse) or decrypted at the
        start and not encrypted again.
        """
        needed = []
        for path in self.environment.get(remove_decrypt.DECRYPTED_FILES_ENV) or []:
            if os.path.isfile(path):
                needed.append(path)
        if not os.path.exists(self._ENCRYPTOR_TOOL_PATH):
            return needed
        try:
            spec = importlib.util.spec_from_file_location(
                'ovirt_engine_remove_encryptor', self._ENCRYPTOR_TOOL_PATH,
            )
            encryptor = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(encryptor)
            config = encryptor._load_crypto_config(self._ENCRYPTOR_CONFIG_PATH)
            needed.extend(
                str(path) for path in encryptor.encrypted_targets(
                    config, magics=(encryptor.ENVELOPE_MAGIC,),
                )
            )
        except Exception as e:
            self.logger.debug('Unable to look for encrypted files', exc_info=True)
            self.logger.warning(
                _('Could not check for files still encrypted: {error}').format(
                    error=e,
                )
            )
        return sorted(set(needed))

    def _remove_stale_secrets(self, keep_dek=False):
        for path in self._ENCRYPTOR_STALE_SECRETS:
            if keep_dek and path == self._DEK_PATH:
                continue
            self._destroy(path)

    def _forget_kek_passphrase(self):
        """Stopping the KEK agent wipes the passphrase it held in memory, and
        disabling it keeps it from coming back at the next boot."""
        rc, stdout, stderr = self.execute(
            ('systemctl', 'disable', '--now', self._KEK_AGENT_SERVICE),
            raiseOnError=False,
        )
        if rc != 0:
            self.logger.debug(
                'Could not stop %s: %s', self._KEK_AGENT_SERVICE, stderr,
            )
        else:
            self._audit(
                'operation=key-destroy key=kek-passphrase service=%s '
                'status=success' % self._KEK_AGENT_SERVICE
            )

    def _remove_encryptor_private_key(self):
        self._destroy(self._ENCRYPTOR_PRIVATE_KEY_PATH)

    def _remove_dwh_scram_runtime(self):
        """Takes back the SCRAM runtime lent to the Data Warehouse ETL.

        The links point into the engine's own tree, which is about to go. Left
        behind they become dangling entries on the ETL's classpath - which is
        worse than nothing there, and would outlive the package that put them
        there.
        """
        for directory in oenginecons.FileLocations.DWH_JAVA_LIB_DIRS:
            for jar in oenginecons.FileLocations.SCRAM_RUNTIME_JARS:
                link = os.path.join(
                    directory,
                    '{prefix}{jar}'.format(
                        prefix=(
                            oenginecons.FileLocations.SCRAM_RUNTIME_LINK_PREFIX
                        ),
                        jar=jar,
                    ),
                )
                try:
                    if os.path.islink(link) or os.path.exists(link):
                        os.remove(link)
                except OSError as e:
                    # Said, not raised: the engine is being removed either way,
                    # and a link that could not be taken back must not stop it.
                    self.logger.warning(
                        _('Could not remove {link}: {error}').format(
                            link=link,
                            error=e,
                        )
                    )

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.environment.setdefault(
            oenginecons.RemoveEnv.REMOVE_ENGINE,
            None
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_CUSTOMIZATION,
        after=(
            osetupcons.Stages.REMOVE_CUSTOMIZATION_COMMON,
        ),
        condition=lambda self: not self.environment[
            osetupcons.RemoveEnv.REMOVE_ALL
        ],
    )
    def _customization(self):
        if (
            self.environment[
                oenginecons.RemoveEnv.REMOVE_ENGINE
            ] is None and
            self.environment[
                oenginecons.CoreEnv.ENABLE
            ]
        ):
            self.environment[
                oenginecons.RemoveEnv.REMOVE_ENGINE
            ] = dialog.queryBoolean(
                dialog=self.dialog,
                name='OVESETUP_REMOVE_ENGINE',
                note=_(
                    'Do you want to remove the engine? '
                    '(@VALUES@) [@DEFAULT@]: '
                ),
                prompt=True,
                true=_('Yes'),
                false=_('No'),
                default=False,
            )
            if self.environment[oenginecons.RemoveEnv.REMOVE_ENGINE]:
                self.environment[osetupcons.RemoveEnv.REMOVE_OPTIONS].append(
                    oenginecons.Const.ENGINE_PACKAGE_NAME
                )
                # TODO: avoid to hard-coded group names here.
                # we should modify all groups with some engine prefix so we
                # know what they are, then just iterate based on prefix.
                # alternatively have a group of groups.
                # Put as much information within uninstall so that the
                # uninstall will be as stupid as we can have.
                # as uninstall will be modified after upgrade, new groups will
                # be available there anyway... so we can modify names.
                # also, if there is some kind of a problem we can have
                # temporary mapping between old and new.
                # anything that will require update of both setup and remove
                # on regular basis.
                self.environment[
                    osetupcons.RemoveEnv.REMOVE_SPEC_OPTION_GROUP_LIST
                ].extend(
                    [
                        'ca_pki',
                        'ca_pki',
                        'ca_config',
                        'ssl',
                        'versionlock',
                    ]
                )

    @plugin.event(
        stage=plugin.Stages.STAGE_CLOSEUP,
        before=(
            osetupcons.Stages.DIALOG_TITLES_E_SUMMARY,
        ),
        after=(
            osetupcons.Stages.DIALOG_TITLES_S_SUMMARY,
            remove_decrypt.REENCRYPTED_EVENT,
        ),
        condition=lambda self: (
            self.environment[
                osetupcons.RemoveEnv.REMOVE_ALL
            ] or
            self.environment[
                oenginecons.RemoveEnv.REMOVE_ENGINE
            ]
        ),
    )
    def _closeup(self):
        self.dialog.note(
            text=_(
                '{description} has been removed'
            ).format(
                description=oenginecons.Const.ENGINE_PACKAGE_NAME,
            ),
        )
        # Looked at before config.json is replaced: it says where the files are.
        needed = self._dek_still_needed()
        if not needed:
            self._write_encryptor_config()
        else:
            # Left as it is: what stays installed reads it to find the DEK.
            # Destroying the DEK now would leave these unreadable for good.
            self.logger.warning(
                _(
                    'The DEK ({dek}) and the KEK passphrase are kept: these '
                    'files are still encrypted under it, or could not be '
                    'encrypted again:\n{files}\nRemove them, or the component '
                    'that owns them, and then remove {dek}'
                ).format(dek=self._DEK_PATH, files='\n'.join(needed))
            )
            self._audit(
                'operation=key-destroy file=%s status=kept files=%s'
                % (self._DEK_PATH, ','.join(needed)),
                syslog.LOG_WARNING,
            )
        self._remove_stale_secrets(keep_dek=bool(needed))
        if not needed:
            self._forget_kek_passphrase()
        self._remove_encryptor_private_key()
        self._remove_dwh_scram_runtime()
        self.environment[
            oenginecons.CoreEnv.ENABLE
        ] = False


# vim: expandtab tabstop=4 shiftwidth=4
