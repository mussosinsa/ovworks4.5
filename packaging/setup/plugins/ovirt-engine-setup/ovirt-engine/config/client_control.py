#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#

"""Client serial number and source IP access-control setup plugin."""

import base64
import gettext
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile

from otopi import plugin
from otopi import util

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
_VAULT_PASSPHRASE_TOOL_PATH = \
    '/usr/share/ovirt-engine/encryptor/vault_passphrase.py'
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
        """Restore at-rest encryption if setup aborts before closeup."""
        path = oenginecons.FileLocations.AAA_JDBC_CONFIG_DB
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

    def _preflight_vault_transit(self, config):
        vault = config.get('vault_transit')
        if not isinstance(vault, dict) or not vault.get('enabled', False):
            return
        if not os.path.exists(_VAULT_PASSPHRASE_TOOL_PATH):
            raise RuntimeError(
                _('Vault Transit is enabled but its helper is missing: %s') %
                _VAULT_PASSPHRASE_TOOL_PATH
            )
        completed = subprocess.run(
            [
                '/usr/bin/python3',
                _VAULT_PASSPHRASE_TOOL_PATH,
                '--check',
                '--config',
                _ENCRYPTOR_CONFIG_PATH,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
        )
        if completed.returncode != 0:
            output = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(
                _('Vault Transit preflight failed: %s') % output
            )
        self.logger.info(completed.stdout.strip())

    @plugin.event(
        stage=plugin.Stages.STAGE_CUSTOMIZATION,
        condition=lambda self: self.environment[oenginecons.CoreEnv.ENABLE],
    )
    def _customization(self):
        encryptor_config = self._read_encryptor_config()
        self._preflight_vault_transit(encryptor_config)

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
        has_secret_file = 'secret_file' in config
        merged = dict(_ENCRYPTOR_DEFAULT_CONFIG)
        merged.update(config)
        vault = merged.get('vault_transit')
        if (
            isinstance(vault, dict) and
            vault.get('enabled', False) and
            not has_secret_file
        ):
            merged.pop('secret_file', None)
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
        vault = config.get('vault_transit')
        vault_enabled = (
            isinstance(vault, dict) and vault.get('enabled', False)
        )
        # Pure Vault mode does not need a passphrase. Create one only when the
        # operator explicitly configured secret_file, in which case closeup
        # immediately converts it to an OVVLT001 recovery envelope.
        if vault_enabled and not config.get('secret_file'):
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
                secret = base64.urlsafe_b64encode(os.urandom(48))
                os.write(descriptor, secret + b'\n')
            finally:
                os.close(descriptor)
        os.chmod(secret_file, 0o600)
        shutil.chown(
            secret_file,
            user=self.environment[osetupcons.SystemEnv.USER_ENGINE],
            group=self.environment[osetupcons.SystemEnv.GROUP_ENGINE],
        )

    def _protect_encryptor_secret_file(self, config_path, config):
        """Wrap an existing legacy passphrase when Vault mode is enabled."""
        vault = config.get('vault_transit')
        if not isinstance(vault, dict) or not vault.get('enabled', False):
            return
        secret_file = config.get('secret_file')
        if not secret_file or not os.path.exists(secret_file):
            return
        try:
            with open(secret_file, 'rb') as stream:
                if stream.read(8) == b'OVVLT001':
                    return
        except OSError as exception:
            raise RuntimeError(
                _('Unable to inspect encryptor passphrase file: %s') % exception
            )
        if not os.path.exists(_VAULT_PASSPHRASE_TOOL_PATH):
            raise RuntimeError(
                _('Vault passphrase tool not found: %s') %
                _VAULT_PASSPHRASE_TOOL_PATH
            )
        completed = subprocess.run(
            [
                '/usr/bin/python3',
                _VAULT_PASSPHRASE_TOOL_PATH,
                '--encrypt-in-place',
                '--config',
                config_path,
                secret_file,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
        )
        if completed.returncode != 0:
            output = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(
                _('Vault passphrase protection failed: %s') % output
            )
        with open(secret_file, 'rb') as stream:
            if stream.read(8) != b'OVVLT001':
                raise RuntimeError(
                    _('Vault passphrase protection did not produce OVVLT001')
                )
        self.logger.info(
            _('Protected encryptor passphrase with Vault Transit: %s') %
            secret_file
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
            os.chmod(temporary_path, 0o600)
            shutil.chown(
                temporary_path,
                user=self.environment[osetupcons.SystemEnv.USER_ENGINE],
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
        config['serialNum'] = self.environment[
            _SERIAL_NUMBER_ENV
        ]
        self._ensure_encryptor_secret_file(config)
        self._replace_encryptor_config(
            path=path,
            content=json.dumps(config, indent=4, sort_keys=True) + '\n',
        )
        self._protect_encryptor_secret_file(path, config)
        self._encrypt_configuration_files(path)
