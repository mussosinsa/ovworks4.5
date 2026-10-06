#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#

"""Client serial number and source IP access-control setup plugin."""

import base64
import gettext
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time

from otopi import plugin
from otopi import util

from ovirt_engine import csprng
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
_SERIAL_NUMBER_ENV = getattr(
    _CLIENT_CONTROL_ENV,
    'SERIAL_NUMBER',
    'OVESETUP_CLIENT_CONTROL/serialNumber',
)
_ENCRYPTOR_CONFIG_PATH = getattr(
    oenginecons.FileLocations,
    'OVIRT_ENGINE_ENCRYPTOR_CONFIG',
    '/etc/ovirt-engine/encryptor/config.json',
)

_ENCRYPTOR_TOOL_PATH = '/usr/share/ovirt-engine/encryptor/encrypt_conf_files.py'
_ENCRYPTOR_FILE_TOOL_PATH = '/usr/share/ovirt-engine/encryptor/encryptor.py'
_KEK_AGENT_TOOL_PATH = '/usr/share/ovirt-engine/encryptor/kek_agent.py'
_KEK_AGENT_SERVICE = 'ovirt-engine-kek-agent.service'
_KEK_AGENT_UNIT_PATH = '/usr/lib/systemd/system/ovirt-engine-kek-agent.service'
_ENCRYPTED_MAGICS = (b'OVENC001', b'OVVLT001')
_ENCRYPTOR_SECRET_FILE = '/etc/ovirt-engine/encryptor/passphrase'
_AAA_JDBC_SETUP_ADMIN_USER = 'osetup.aaa_jdbc.config.setup.admin.user'
# Keep this event name local to the plugin. setup-plugin-ovirt-engine and
# setup-plugin-ovirt-engine-common can be upgraded independently, so importing a
# newly added attribute from the common Stages class would make plugin loading
# fail until both RPMs are updated in lockstep.
_DB_CREDENTIALS_ENCRYPTED = 'osetup.db.connection.credentials.encrypted'
_ENCRYPTOR_DEFAULT_CONFIG = {
    'encrypt_flag': 'NO',
    'iterations': 200000,
    'watch_path': [
        '/etc/ovirt-engine',
        '/etc/ovirt-engine-dwh',
    ],
    'allowed_files': [
        '10-setup-database.conf',
        '10-setup-dwh-database.conf',
        'internal.properties',
    ],
    'secret_file': _ENCRYPTOR_SECRET_FILE,
    'legacy_cbc': {
        'enabled': False,
    },
}


@util.export
class Plugin(plugin.PluginBase):
    """Collect and persist the client-control settings."""

    _DEFAULT_SERIAL_NUMBER = 'saeoll20250322'
    _LOOPBACK_ADDRESS = '127.0.0.1'
    _SERIAL_PATTERN = re.compile(r'^[A-Za-z0-9._-]{1,128}$')
    _REQUIRE_IP_PATTERN = re.compile(
        r'^\s*Require\s+ip\s+(.+?)\s*$',
        re.IGNORECASE,
    )

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)
        self._memory_kek = False
        self._customized = False
        self._internal_decrypted = False

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.environment.setdefault(
            _ALLOWED_IPS_ENV,
            None,
        )
        self.environment.setdefault(
            _SERIAL_NUMBER_ENV,
            None,
        )
    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        before=(_AAA_JDBC_SETUP_ADMIN_USER,),
        condition=lambda self: (
            self.environment[oenginecons.CoreEnv.ENABLE] and
            not self.environment[osetupcons.CoreEnv.DEVELOPER_MODE]
        ),
    )
    def _decrypt_internal_configuration(self):
        path = oenginecons.FileLocations.AAA_JDBC_CONFIG_DB
        if not self._is_encrypted_file(path):
            return
        if not os.path.exists(_ENCRYPTOR_FILE_TOOL_PATH):
            raise RuntimeError(
                _('Encryptor tool not found: %s') % _ENCRYPTOR_FILE_TOOL_PATH
            )
        completed = subprocess.run(
            [
                '/usr/bin/python3',
                _ENCRYPTOR_FILE_TOOL_PATH,
                '--decrypt',
                '--deny-legacy-cbc',
                '--config',
                _ENCRYPTOR_CONFIG_PATH,
                path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
        )
        if completed.returncode != 0:
            output = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(
                _('AAA JDBC configuration decryption failed: %s') % output
            )
        self._internal_decrypted = True
        self.logger.info(
            _('Decrypted AAA JDBC configuration for engine-setup: %s') % path
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_CLEANUP,
        condition=lambda self: (
            self.environment[oenginecons.CoreEnv.ENABLE] and
            not self.environment[osetupcons.CoreEnv.DEVELOPER_MODE]
        ),
    )
    def _cleanup_internal_configuration(self):
        """Restore at-rest encryption if setup aborts before closeup.

        Only of what this run decrypted: a file that was never encrypted (a first
        installation) has no key to be encrypted with before closeup creates one.
        """
        path = oenginecons.FileLocations.AAA_JDBC_CONFIG_DB
        if not self._internal_decrypted:
            return
        if not os.path.isfile(path) or self._is_encrypted_file(path):
            return
        if not os.path.exists(_ENCRYPTOR_FILE_TOOL_PATH):
            self.logger.error(
                _('Cannot re-encrypt AAA JDBC configuration; tool missing: %s'),
                _ENCRYPTOR_FILE_TOOL_PATH,
            )
            return
        completed = subprocess.run(
            [
                '/usr/bin/python3',
                _ENCRYPTOR_FILE_TOOL_PATH,
                '--encrypt',
                '--config',
                _ENCRYPTOR_CONFIG_PATH,
                path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
        )
        if completed.returncode != 0:
            output = (completed.stderr or completed.stdout).strip()
            self.logger.error(
                _('Failed to restore AAA JDBC configuration encryption: %s'),
                output,
            )
        else:
            self.logger.info(
                _('Restored AAA JDBC configuration encryption: %s') % path
            )

    def _read_encryptor_config(self):
        path = _ENCRYPTOR_CONFIG_PATH
        if not os.path.exists(path):
            return {}
        try:
            with open(path, encoding='utf-8') as config_file:
                value = json.load(config_file)
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError) as exception:
            raise RuntimeError(
                _(
                    'Unable to read client-control configuration: %s'
                ) % exception
            )

    def _read_allowed_ips(self):
        path = self.environment[
            oenginecons.ApacheEnv.HTTPD_CONF_OVIRT_ENGINE
        ]
        addresses = []
        if os.path.exists(path):
            with open(path, encoding='utf-8') as proxy_file:
                for line in proxy_file:
                    match = self._REQUIRE_IP_PATTERN.match(line)
                    if match:
                        addresses.extend(match.group(1).split())
        return addresses or [self._LOOPBACK_ADDRESS]

    def _normalize_allowed_ips(self, value):
        addresses = []
        for candidate in re.split(r'[\s,]+', value.strip()):
            if not candidate:
                continue
            try:
                normalized = str(ipaddress.ip_network(candidate, strict=False))
                if '/' not in candidate:
                    normalized = str(ipaddress.ip_address(candidate))
            except ValueError:
                raise RuntimeError(
                    _('Invalid client IP address or network: %s') % candidate
                )
            if normalized not in addresses:
                addresses.append(normalized)

        if self._LOOPBACK_ADDRESS not in addresses:
            addresses.insert(0, self._LOOPBACK_ADDRESS)
        return addresses

    def _load_encryptor(self):
        spec = importlib.util.spec_from_file_location(
            'ovirt_engine_setup_encryptor',
            _ENCRYPTOR_FILE_TOOL_PATH,
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _query_secret(self, name, note):
        """A hidden answer, as a bytearray that can be overwritten after use.

        Asked only, never taken from an answer file or the environment, and never put in the
        environment: otopi writes that to the answer file and the log.
        """
        return bytearray(
            self.dialog.queryString(
                name=name,
                note=note,
                prompt=True,
                hidden=True,
            ).encode('utf-8')
        )

    def _database_credential_files(self):
        return [
            path for path in (
                oenginecons.FileLocations.OVIRT_ENGINE_SERVICE_CONFIG_DATABASE,
                oenginecons.FileLocations.OVIRT_ENGINE_SERVICE_CONFIG_DWH_DATABASE,
                oenginecons.FileLocations.AAA_JDBC_CONFIG_DB,
            ) if os.path.isfile(path)
        ]

    def _credential_file_magics(self):
        magics = set()
        for path in self._database_credential_files():
            try:
                with open(path, 'rb') as stream:
                    magics.add(stream.read(8))
            except OSError:
                pass
        return magics

    def _uses_memory_kek(self, config):
        """Whether the KEK passphrase is typed in here and held in memory.

        Always, but for an installation whose files are still encrypted under a
        passphrase file (OVENC001 and secret_file on disk): it keeps working that
        way until kek_agent.py --migrate moves it. Vault is not used by
        engine-setup; files still encrypted by Vault (OVVLT001) must be moved first.
        """
        magics = self._credential_file_magics()
        if b'OVVLT001' in magics:
            raise RuntimeError(
                _(
                    'Database configuration files are encrypted by Vault '
                    'Transit (OVVLT001), which engine-setup no longer uses. '
                    'Move them first: %s --migrate'
                ) % _KEK_AGENT_TOOL_PATH
            )
        memory = config.get('kek_agent')
        memory_enabled = (
            isinstance(memory, dict) and memory.get('enabled', False) is True
        )
        if (
            not memory_enabled and
            b'OVENC001' in magics and
            os.path.exists(config.get('secret_file', _ENCRYPTOR_SECRET_FILE))
        ):
            self.logger.info(
                _(
                    'The configuration files are encrypted with a passphrase '
                    'file; to hold the passphrase in memory instead run %s '
                    '--migrate'
                ) % _KEK_AGENT_TOOL_PATH
            )
            return False
        # From here the passphrase is asked for and held in memory. Without the
        # tool that holds it nothing can be encrypted at closeup, so say so now,
        # before anything is changed, rather than skip the question.
        for path in (_KEK_AGENT_TOOL_PATH, _KEK_AGENT_UNIT_PATH):
            if not os.path.exists(path):
                raise RuntimeError(
                    _(
                        'The KEK passphrase is held in memory by %s, but %s '
                        'is not installed. Install the updated packages (or '
                        'copy it into place: see '
                        'ovirt-engine-check-deployment.sh) and run '
                        'engine-setup again'
                    ) % (_KEK_AGENT_SERVICE, path)
                )
        return True

    def _start_kek_agent(self):
        completed = subprocess.run(
            ['systemctl', 'enable', '--now', _KEK_AGENT_SERVICE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                _('KEK agent could not be started (%s): %s') % (
                    _KEK_AGENT_SERVICE,
                    (completed.stderr or completed.stdout).strip(),
                )
            )

    def _wait_for_kek_agent(self, encryptor, socket_path, timeout=20):
        """Whether the agent holds a passphrase, once it answers at all.

        A unit installed before it became Type=notify returns from systemctl
        start before its socket exists; the first few connections are refused.
        """
        deadline = time.monotonic() + timeout
        while True:
            try:
                return encryptor.memory_passphrase_loaded(socket_path)
            except encryptor.EncryptorError as error:
                if time.monotonic() >= deadline:
                    raise encryptor.EncryptorError(
                        '%s (see: systemctl status %s; journalctl -u %s)' % (
                            error, _KEK_AGENT_SERVICE, _KEK_AGENT_SERVICE,
                        )
                    )
                time.sleep(0.5)

    def _ensure_memory_kek(self, config):
        """Asks for the passphrase the KEK is derived from and hands it to the KEK agent.

        Typed in here, hidden, and held from then on by ovirt-engine-kek-agent.service in
        memory only - never written to config.json, an answer file, the otopi environment, a
        log or any other file. Each configuration file derives its own KEK from it with
        PBKDF2-HMAC-SHA256 (600,000 iterations, a random salt of the file's own), and that KEK
        wraps the file's random DEK (envelope encryption, OVENC001). Key creation and every
        failure are recorded as audit events.
        """
        encryptor = self._load_encryptor()
        memory = config.get('kek_agent')
        socket_path = (
            memory.get('socket', encryptor.MEMORY_KEK_SOCKET)
            if isinstance(memory, dict) else encryptor.MEMORY_KEK_SOCKET
        )
        probe = None
        for path in self._database_credential_files():
            with open(path, 'rb') as stream:
                content = stream.read()
            if content.startswith(b'OVENC001'):
                probe = content
                break
        try:
            self._start_kek_agent()
            loaded = self._wait_for_kek_agent(encryptor, socket_path)
        except Exception as error:
            self._record_kek_event('KEY_CREATION_FAILED', error)
            raise RuntimeError(
                _('The KEK agent is not available: %s') % error
            )
        if loaded and probe is not None:
            # The files are encrypted under the passphrase held now (setup
            # already read them with it): nothing to type in again.
            self.logger.info(
                _('The KEK passphrase is already held in memory by %s') %
                _KEK_AGENT_SERVICE
            )
            return
        self.dialog.note(
            text=_(
                'The configuration files that hold the database passwords are '
                'encrypted with a random data key (DEK) per file, wrapped by a '
                'key-encryption key (KEK) derived from a passphrase you type in '
                'now (PBKDF2-HMAC-SHA256, %(iterations)d iterations). The '
                'passphrase is kept in memory only: after a reboot type it in '
                'again with %(tool)s --unlock before the engine can start.'
            ) % {
                'iterations': encryptor.PBKDF2_ITERATIONS,
                'tool': _KEK_AGENT_TOOL_PATH,
            }
        )
        passphrase = None
        for _attempt in range(3):
            passphrase = self._query_secret(
                'OVESETUP_KEK_PASSPHRASE',
                _('KEK passphrase (%d+ characters): ') %
                encryptor.MEMORY_MIN_PASSPHRASE,
            )
            again = None
            try:
                encryptor.check_memory_passphrase(passphrase)
                if probe is not None:
                    # Already encrypted under it: the AES-GCM tag proves the passphrase.
                    encryptor.decrypt_gcm_bytes(probe, passphrase)
                else:
                    again = self._query_secret(
                        'OVESETUP_KEK_PASSPHRASE_CONFIRM',
                        _('KEK passphrase again: '),
                    )
                    if passphrase != again:
                        raise encryptor.EncryptorError(
                            'The two passphrases differ'
                        )
                break
            except encryptor.EncryptorError as error:
                self._record_kek_event('KEY_CREATION_FAILED', error)
                self.logger.warning(str(error))
                encryptor.wipe(passphrase)
                passphrase = None
            finally:
                encryptor.wipe(again)
        if passphrase is None:
            raise RuntimeError(_('No usable KEK passphrase was entered'))
        try:
            encryptor.load_memory_passphrase(socket_path, passphrase)
        except Exception as error:
            self._record_kek_event('KEY_CREATION_FAILED', error)
            raise RuntimeError(
                _('The KEK passphrase could not be held in memory: %s') % error
            )
        finally:
            encryptor.wipe(passphrase)
        self._record_kek_event('KEY_CREATED')
        self.logger.info(
            _('The KEK passphrase is held in memory by %s') % _KEK_AGENT_SERVICE
        )

    def _record_kek_event(self, event, error=None):
        try:
            from ovirt_engine import cryptoevents
        except ImportError:
            return
        fields = {}
        if error is not None:
            fields['reason'] = cryptoevents.reason_for(error)
        try:
            cryptoevents.record(
                getattr(cryptoevents, event), 'engine-setup',
                scheme='OVENC001' if self._memory_kek else None, **fields
            )
        except Exception:
            self.logger.debug('Unable to record %s', event, exc_info=True)

    @plugin.event(
        stage=plugin.Stages.STAGE_CUSTOMIZATION,
        # After the question whether to configure the engine here. Before it the
        # answer is still None, the condition below is false and the whole step -
        # the KEK passphrase, the serial number, the allowed addresses - was
        # skipped on a new installation, while closeup (which runs once the
        # answer is yes) went on to encrypt with a passphrase nobody typed in.
        after=(
            oenginecons.Stages.CORE_ENABLE,
        ),
        before=(
            osetupcons.Stages.DIALOG_TITLES_E_PRODUCT_OPTIONS,
        ),
        condition=lambda self: self.environment[oenginecons.CoreEnv.ENABLE],
    )
    def _customization(self):
        self._customized = True
        encryptor_config = self._read_encryptor_config()
        self._memory_kek = self._uses_memory_kek(encryptor_config)
        if self._memory_kek:
            self._ensure_memory_kek(encryptor_config)

        if self.environment[
            _SERIAL_NUMBER_ENV
        ] is None:
            self.environment[
                _SERIAL_NUMBER_ENV
            ] = self.dialog.queryString(
                name='OVESETUP_CLIENT_CONTROL_SERIAL_NUMBER',
                note=_(
                    'Client serial number used for authentication '
                    '[@DEFAULT@]: '
                ),
                prompt=True,
                default=encryptor_config.get(
                    'serialNum',
                    self._DEFAULT_SERIAL_NUMBER,
                ),
            )

        serial_number = self.environment[
            _SERIAL_NUMBER_ENV
        ]
        if not self._SERIAL_PATTERN.match(serial_number):
            raise RuntimeError(
                _(
                    'Client serial number must contain 1-128 letters, '
                    'digits, dots, underscores, or hyphens'
                )
            )

        if self.environment[_ALLOWED_IPS_ENV] is None:
            self.environment[
                _ALLOWED_IPS_ENV
            ] = self.dialog.queryString(
                name='OVESETUP_CLIENT_CONTROL_ALLOWED_IPS',
                note=_(
                    'Client IP addresses or networks allowed to access the '
                    'engine (comma separated; 127.0.0.1 is always retained) '
                    '[@DEFAULT@]: '
                ),
                prompt=True,
                default=', '.join(self._read_allowed_ips()),
            )

        allowed_ips = self.environment[
            _ALLOWED_IPS_ENV
        ]
        if isinstance(allowed_ips, str):
            allowed_ips = self._normalize_allowed_ips(allowed_ips)
        else:
            allowed_ips = self._normalize_allowed_ips(','.join(allowed_ips))
        self.environment[
            _ALLOWED_IPS_ENV
        ] = allowed_ips

    def _merge_encryptor_defaults(self, config):
        merged = dict(_ENCRYPTOR_DEFAULT_CONFIG)
        merged.update(config)
        # engine-setup does not use Vault: whatever an earlier configuration (or
        # a copy of the old Vault example) said about it is dropped.
        for key in ('vault_transit', 'kek_derivation'):
            merged.pop(key, None)
        if self._memory_kek:
            # The passphrase is held in memory; no file stands in for it.
            merged.pop('secret_file', None)
            memory = config.get('kek_agent')
            merged['kek_agent'] = {
                'enabled': True,
                'socket': (
                    memory.get('socket', '/run/ovirt-engine-kek/agent.sock')
                    if isinstance(memory, dict)
                    else '/run/ovirt-engine-kek/agent.sock'
                ),
            }
        allowed_files = list(merged.get('allowed_files', []))
        if 'internal.properties' not in allowed_files:
            allowed_files.append('internal.properties')
        merged['allowed_files'] = allowed_files
        merged.setdefault('serialNum', self._DEFAULT_SERIAL_NUMBER)
        return merged

    def _is_encrypted_file(self, path):
        try:
            with open(path, 'rb') as candidate:
                prefix = candidate.read(8)
                return prefix in _ENCRYPTED_MAGICS
        except OSError:
            return False

    def _ensure_encryptor_secret_file(self, config):
        memory = config.get('kek_agent')
        if isinstance(memory, dict) and memory.get('enabled', False):
            # The passphrase is held in memory only; no file stands in for it.
            return
        secret_file = config.get('secret_file', _ENCRYPTOR_SECRET_FILE)
        secret_dir = os.path.dirname(secret_file)
        if not os.path.isdir(secret_dir):
            os.makedirs(secret_dir, mode=0o700)
        if not os.path.exists(secret_file):
            descriptor = os.open(
                secret_file,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                secret = base64.urlsafe_b64encode(csprng.token_bytes(48))
                os.write(descriptor, secret + b'\n')
            finally:
                os.close(descriptor)
        os.chmod(secret_file, 0o600)
        shutil.chown(
            secret_file,
            user=self.environment[osetupcons.SystemEnv.USER_ENGINE],
            group=self.environment[osetupcons.SystemEnv.GROUP_ENGINE],
        )

    def _encrypt_configuration_files(self, config_path):
        if not os.path.exists(_ENCRYPTOR_TOOL_PATH):
            raise RuntimeError(
                _('Encryptor tool not found: %s') % _ENCRYPTOR_TOOL_PATH
            )
        completed = subprocess.run(
            [
                '/usr/bin/python3',
                _ENCRYPTOR_TOOL_PATH,
                '--config',
                config_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
        )
        if completed.returncode != 0:
            output = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(
                _('Configuration encryption failed: %s') % output
            )
        required = (
            oenginecons.FileLocations.OVIRT_ENGINE_SERVICE_CONFIG_DATABASE,
            oenginecons.FileLocations.AAA_JDBC_CONFIG_DB,
        )
        missing = [path for path in required if not os.path.exists(path)]
        if missing:
            raise RuntimeError(
                _('Required database credential configuration was not found: %s') %
                ', '.join(missing)
            )
        expected = required + (
            oenginecons.FileLocations.OVIRT_ENGINE_SERVICE_CONFIG_DWH_DATABASE,
        )
        existing = [path for path in expected if os.path.exists(path)]
        unencrypted = [path for path in existing if not self._is_encrypted_file(path)]
        if unencrypted:
            raise RuntimeError(
                _('Database credential configuration was not encrypted: %s') %
                ', '.join(unencrypted)
            )
        self.logger.info(completed.stdout.strip())
        self.logger.info(
            _('Verified encrypted database credential files: %s') %
            ', '.join(existing)
        )

    def _remove_stale_secrets(self):
        """Overwrites and removes a passphrase file or Vault token left behind.

        With the passphrase held in memory nothing is encrypted with them any
        more (a passphrase-file installation is not in this mode), and a secret
        left on disk is exactly what this mode exists to avoid.
        """
        for path in (
            _ENCRYPTOR_SECRET_FILE,
            '/etc/ovirt-engine/encryptor/vault-token',
        ):
            try:
                info = os.lstat(path)
            except OSError:
                continue
            try:
                if stat.S_ISREG(info.st_mode):
                    with open(path, 'r+b', buffering=0) as stream:
                        stream.write(b'\0' * info.st_size)
                        os.fsync(stream.fileno())
                os.unlink(path)
                self.logger.info(_('Removed the unused secret %s') % path)
            except OSError as error:
                self.logger.warning(
                    _('Could not remove the unused secret %s: %s'),
                    path,
                    error,
                )

    def _replace_encryptor_config(self, path, content):
        config_dir = os.path.dirname(path)
        if not os.path.isdir(config_dir):
            os.makedirs(config_dir, mode=0o750)
        # The Engine launcher runs as the engine account and decrypts OVVLT001
        # before Java starts. Repair pre-created root-only directories as well
        # as newly created ones so it can traverse to config.json and the token.
        shutil.chown(
            config_dir,
            user=self.environment[oengcommcons.SystemEnv.USER_ROOT],
            group=self.environment[osetupcons.SystemEnv.GROUP_ENGINE],
        )
        os.chmod(config_dir, 0o750)

        descriptor, temporary_path = tempfile.mkstemp(
            prefix='.config.json.',
            dir=config_dir,
            text=True,
        )
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as config_file:
                config_file.write(content)
                config_file.flush()
                os.fsync(config_file.fileno())
            # Configuration contains no passphrase or KEK. Keep it owned by
            # root and read-only to the Engine group so a compromised service
            # cannot redirect where the KEK passphrase is fetched from.
            os.chmod(temporary_path, 0o640)
            shutil.chown(
                temporary_path,
                user=self.environment[oengcommcons.SystemEnv.USER_ROOT],
                group=self.environment[osetupcons.SystemEnv.GROUP_ENGINE],
            )
            os.replace(temporary_path, path)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)

    @plugin.event(
        stage=plugin.Stages.STAGE_CLOSEUP,
        name=_DB_CREDENTIALS_ENCRYPTED,
        before=(oengcommcons.Stages.CORE_ENGINE_START,),
        condition=lambda self: (
            self.environment[oenginecons.CoreEnv.ENABLE] and
            not self.environment[osetupcons.CoreEnv.DEVELOPER_MODE]
        ),
    )
    def _closeup(self):
        path = _ENCRYPTOR_CONFIG_PATH
        config = self._merge_encryptor_defaults(
            self._read_encryptor_config()
        )
        if not self._customized:
            # Nothing was asked (no passphrase is held, no serial number was
            # given): encrypting now would fail half way or lose settings.
            raise RuntimeError(
                _(
                    'Client control and KEK customization did not run; '
                    'configuration files were not encrypted'
                )
            )
        config['serialNum'] = self.environment[
            _SERIAL_NUMBER_ENV
        ]
        self._ensure_encryptor_secret_file(config)
        self._replace_encryptor_config(
            path=path,
            content=json.dumps(config, indent=4, sort_keys=True) + '\n',
        )
        self._encrypt_configuration_files(path)
        if self._memory_kek:
            self._remove_stale_secrets()
