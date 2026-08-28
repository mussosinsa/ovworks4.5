#
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


import gettext
import glob
import importlib.util
import os
import re

from . import base


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine')

_ENCRYPTOR_PATH = '/usr/share/ovirt-engine/encryptor/encryptor.py'
_ENCRYPTOR_CONFIG_PATH = '/etc/ovirt-engine/encryptor/config.json'
_ENCRYPTED_CONFIG_BASENAMES = frozenset((
    '10-setup-database.conf',
    '10-setup-dwh-database.conf',
    'internal.properties',
))
_ENCRYPTED_MAGICS = (b'OVENC001', b'OVVLT001')


def _load_encryptor_module():
    spec = importlib.util.spec_from_file_location(
        'ovirt_engine_config_encryptor',
        _ENCRYPTOR_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ConfigFile(base.Base):
    """
    Parsing of shell style config file.
    Follow closly the java LocalConfig implementaiton.
    """

    _EMPTY_LINE = re.compile(r'^\s*(#.*|)$')
    _KEY_VALUE_EXPRESSION = re.compile(r'^\s*(?P<key>\w+)=(?P<value>.*)$')

    @property
    def values(self):
        return self._values

    def _loadLine(self, line):
        emptyMatch = self._EMPTY_LINE.search(line)
        if emptyMatch is None:
            keyValueMatch = self._KEY_VALUE_EXPRESSION.search(line)
            if keyValueMatch is None:
                raise RuntimeError(_('Invalid sytax'))
            self._values[keyValueMatch.group('key')] = self.expandString(
                keyValueMatch.group('value')
            )

    def _loadFileContent(self, file):
        with open(file, 'rb') as f:
            content = f.read()
        if (
            os.path.basename(file) in _ENCRYPTED_CONFIG_BASENAMES and
            content.startswith(_ENCRYPTED_MAGICS)
        ):
            if not os.path.exists(_ENCRYPTOR_PATH):
                raise RuntimeError(
                    _('Encryptor tool is missing: {path}').format(
                        path=_ENCRYPTOR_PATH,
                    )
                )
            encryptor = _load_encryptor_module()
            config = encryptor._load_crypto_config(_ENCRYPTOR_CONFIG_PATH)
            transit_client = encryptor.vault_client_from_config(config)
            passphrase = None
            if content.startswith(encryptor.MAGIC):
                passphrase = encryptor.obtain_passphrase(
                    config, transit_client=transit_client
                )
            content = encryptor.decrypt_bytes(
                content,
                passphrase,
                config,
                transit_client=transit_client,
            )
        return content.decode('utf-8')

    def __init__(self, files=[]):
        super(ConfigFile, self).__init__()

        self._values = {}

        for file in files:
            self.loadFile(file)
            for filed in sorted(
                glob.glob(
                    os.path.join(
                        '%s.d' % file,
                        '*.conf',
                    )
                )
            ):
                self.loadFile(filed)

    def loadFile(self, file):
        if os.path.exists(file):
            self.logger.debug("loading config '%s'", file)
            index = 0
            try:
                for line in self._loadFileContent(file).splitlines():
                    index += 1
                    self._loadLine(line)
            except Exception as e:
                self.logger.error(
                    "File '%s' index %d error" % (file, index),
                    exc_info=True,
                )
                raise RuntimeError(
                    _(
                        "Cannot parse configuration file "
                        "'{file}' line {line}: {error}"
                    ).format(
                        file=file,
                        line=index,
                        error=e
                    )
                )

    def expandString(self, value):
        ret = ""

        escape = False
        inQuotes = False
        index = 0
        while (index < len(value)):
            c = value[index]
            index += 1
            if escape:
                escape = False
                ret += c
            else:
                if c == '\\':
                    escape = True
                elif c == '$':
                    if value[index] != '{':
                        raise RuntimeError('Malformed variable assignment')
                    index += 1
                    i = value.find('}', index)
                    if i == -1:
                        raise RuntimeError('Malformed variable assignment')
                    name = value[index:i]
                    index = i + 1
                    ret += self._values.get(name, "")
                elif c == '"':
                    inQuotes = not inQuotes
                elif c in (' ', '#'):
                    if inQuotes:
                        ret += c
                    else:
                        index = len(value)
                else:
                    ret += c

        return ret

    def get(self, name, default=None):
        return self._values.get(name, default)

    def getboolean(self, name, default=None):
        text = self.get(name)
        if text is None:
            return default
        else:
            return text.lower() in ('t', 'true', 'y', 'yes', '1')

    def getinteger(self, name, default=None):
        value = self.get(name)
        if value is None:
            return default
        else:
            return int(value)


# vim: expandtab tabstop=4 shiftwidth=4
