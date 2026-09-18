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
from . import cryptoevents


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


def _scheme_of(content):
    for magic in _ENCRYPTED_MAGICS:
        if content.startswith(magic):
            return magic.decode('ascii')
    return None


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
            envelope = content
            try:
                content = self._decrypt(file, content)
                # Recorded as well as the failures. "Nothing in the event list" is the same
                # picture whether every file decrypted or none of them was ever encrypted, and
                # the point of the record is to be able to tell those apart.
                self._recordCryptoEvent(
                    cryptoevents.DECRYPTION_COMPLETED,
                    file,
                    envelope,
                )
            except Exception as error:
                # Recorded before it is re-raised. This runs before the Java daemon exists, so
                # the failure that follows stops the engine from starting and there is nothing
                # left to write an audit event - the event list would say nothing at all, which
                # is what it also says when every file decrypted cleanly.
                self._recordCryptoEvent(
                    cryptoevents.DECRYPTION_FAILED,
                    file,
                    envelope,
                    reason=cryptoevents.reason_for(error),
                )
                raise
        return content.decode('utf-8')

    def _decrypt(self, file, content):
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
        return encryptor.decrypt_bytes(
            content,
            passphrase,
            config,
            transit_client=transit_client,
        )

    def _recordCryptoEvent(self, event, file, content, reason=None):
        """Leaves the result where the engine can report it, when asked to.

        Only the caller that says who it is gets events: this class is read by every tool that
        loads the engine's configuration, and an event per tool per invocation would say
        nothing about the engine's own start, which is the thing worth recording.
        """
        if self._cryptoEventSource is None:
            return
        cryptoevents.record(
            event,
            self._cryptoEventSource,
            file=file,
            scheme=_scheme_of(content),
            reason=reason,
        )

    def __init__(self, files=[], cryptoEventSource=None):
        """@param cryptoEventSource what to record decryption as, or None to record nothing"""
        super(ConfigFile, self).__init__()

        self._values = {}
        self._cryptoEventSource = cryptoEventSource

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
