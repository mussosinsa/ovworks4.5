#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""Engine-remove plugin."""


import gettext
import os

from otopi import plugin
from otopi import util

from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons

from ovirt_setup_lib import dialog


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """Engine-remove plugin."""
    _ENCRYPTOR_CONFIG_PATH = '/etc/ovirt-engine/encryptor/config.json'
    _ENCRYPTOR_PRIVATE_KEY_PATH = '/etc/ovirt-engine/encryptor/private_pkcs8.der'
    _ENCRYPTOR_CONFIG_CONTENT = """{
    "watch_path": [
        "/etc/ovirt-engine",
        "/etc/ovirt-engine-dwh"
    ],
    "encrypt_flag": "NO",
    "serialNum": "saeoll20250322",
    "iterations": 200000,
    "salt": "6vMPyG52nDht+DTitl5zRQ==",
    "nonce": "RDOm3KZiwA4Aq/Iu",
    "decrypt_key_ciphertext": "i885Q0KgJooluYRyErQdW1DDf76QTQb3aYuFwo4F91fnpFUhJf2iKP7z7TTVZs/5",
    "decrypt_key": "853cc5671453bbd9b2552354e941926812220aad114577c72372e2f5fa2ec501"
}
"""

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    def _write_encryptor_config(self):
        config_dir = os.path.dirname(self._ENCRYPTOR_CONFIG_PATH)
        if config_dir and not os.path.isdir(config_dir):
            os.makedirs(config_dir, mode=0o700)

        with open(self._ENCRYPTOR_CONFIG_PATH, 'w', encoding='utf-8') as config_file:
            config_file.write(self._ENCRYPTOR_CONFIG_CONTENT)

    def _remove_encryptor_private_key(self):
        if os.path.exists(self._ENCRYPTOR_PRIVATE_KEY_PATH):
            os.remove(self._ENCRYPTOR_PRIVATE_KEY_PATH)

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
        self._write_encryptor_config()
        self._remove_encryptor_private_key()
        self.environment[
            oenginecons.CoreEnv.ENABLE
        ] = False


# vim: expandtab tabstop=4 shiftwidth=4
