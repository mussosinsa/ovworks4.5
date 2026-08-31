#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""aaa plugin."""


import gettext
import random
import string
import re

from otopi import plugin
from otopi import util

from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons
from ovirt_engine_setup.engine import vdcoption
from ovirt_engine_setup.engine_common import constants as oengcommcons
from ovirt_engine_setup.engine_common import database


try:
    import pwquality
    _use_pwquality = True
except ImportError:
    # do not force this optional feature
    _use_pwquality = False


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


@util.export
class Plugin(plugin.PluginBase):
    """aaa plugin."""

    _MIN_ADMIN_PASSWORD_LENGTH = 12
    _DEFAULT_REPEAT_LIMIT = 3
    _DEFAULT_SEQUENCE_LENGTH = 4
    _MAX_PATTERN_LENGTH = 4

    # Runs that are considered sequential. Both directions are rejected, so each
    # run is listed once. The keyboard rows cover 'qwer', 'asdf' and the like,
    # which the alphabet and digit runs alone would not catch.
    _SEQUENCES = (
        '0123456789',
        'abcdefghijklmnopqrstuvwxyz',
        '`1234567890-=',
        'qwertyuiop[]\\',
        "asdfghjkl;'",
        'zxcvbnm,./',
        '~!@#$%^&*()_+',
    )

    _WEAK_WORDS = (
        'password',
        'admin',
        'ovirt',
        'engine',
        'welcome',
        'qwerty',
    )

    @staticmethod
    def _generatePassword():
        return ''.join([
            random.SystemRandom().choice(
                string.ascii_letters +
                string.digits
            ) for i in range(22)
        ])

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    def _policyEnabled(self, key):
        value = self.environment[key]
        if isinstance(value, bool):
            return value
        return str(value).lower() in ('1', 'true', 'yes', 'on')

    def _policyInt(self, key, fallback):
        try:
            return int(self.environment[key])
        except (TypeError, ValueError):
            self.logger.warning(
                _(
                    'Invalid value for {key}, using {fallback}'
                ).format(
                    key=key,
                    fallback=fallback,
                )
            )
            return fallback

    def _hasRepetition(self, lowered_password, repeat_limit):
        if repeat_limit > 1:
            if re.search(
                r'(.)\1{%d}' % (repeat_limit - 1),
                lowered_password,
            ) is not None:
                return True

        # a repeated block such as 'abab' or '123123' is as guessable as a
        # repeated character
        for length in range(2, self._MAX_PATTERN_LENGTH + 1):
            for index in range(len(lowered_password) - 2 * length + 1):
                block = lowered_password[index:index + length]
                if block == lowered_password[
                    index + length:index + 2 * length
                ]:
                    return True

        return False

    def _hasSequence(self, lowered_password, sequence_length):
        if sequence_length < 2 or len(lowered_password) < sequence_length:
            return False
        for index in range(len(lowered_password) - sequence_length + 1):
            token = lowered_password[index:index + sequence_length]
            for sequence in self._SEQUENCES:
                if token in sequence or token[::-1] in sequence:
                    return True
        return False

    def _validateAdminPasswordPolicy(self, password):
        admin_user = self.environment[
            oenginecons.ConfigEnv.ADMIN_USER
        ].split('@', 1)[0].lower()

        min_length = self._policyInt(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_MIN_LENGTH,
            self._MIN_ADMIN_PASSWORD_LENGTH,
        )
        if len(password) < min_length:
            raise RuntimeError(
                _(
                    'Password must be at least {length} characters long'
                ).format(
                    length=min_length,
                )
            )

        complexity_checks = (
            (
                oenginecons.ConfigEnv.ADMIN_PASSWORD_REQUIRE_LOWERCASE,
                r'[a-z]',
                _('Password must contain a lowercase letter'),
            ),
            (
                oenginecons.ConfigEnv.ADMIN_PASSWORD_REQUIRE_UPPERCASE,
                r'[A-Z]',
                _('Password must contain an uppercase letter'),
            ),
            (
                oenginecons.ConfigEnv.ADMIN_PASSWORD_REQUIRE_DIGIT,
                r'[0-9]',
                _('Password must contain a digit'),
            ),
            (
                oenginecons.ConfigEnv.ADMIN_PASSWORD_REQUIRE_SPECIAL,
                r'[^A-Za-z0-9]',
                _('Password must contain a special character'),
            ),
        )
        for key, pattern, message in complexity_checks:
            if self._policyEnabled(key) and re.search(pattern, password) is None:
                raise RuntimeError(message)

        lowered_password = password.lower()

        # Only equality is rejected. Forbidding the account name anywhere inside
        # the password used to reject otherwise strong passwords for no gain.
        if self._policyEnabled(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_FORBID_SAME_AS_USER_ID
        ) and admin_user and lowered_password == admin_user:
            raise RuntimeError(
                _('Password must not be identical to the account name')
            )

        if self._policyEnabled(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_FORBID_COMMON_WORDS
        ):
            for weak_word in self._WEAK_WORDS:
                if weak_word in lowered_password:
                    raise RuntimeError(
                        _('Password must not contain common dictionary words')
                    )

        if self._policyEnabled(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_FORBID_SEQUENTIAL
        ):
            sequence_length = self._policyInt(
                oenginecons.ConfigEnv.ADMIN_PASSWORD_SEQUENCE_LENGTH,
                self._DEFAULT_SEQUENCE_LENGTH,
            )
            if self._hasSequence(lowered_password, sequence_length):
                raise RuntimeError(
                    _(
                        'Password must not contain {length} alphabetical, '
                        'numerical or keyboard sequential characters'
                    ).format(
                        length=sequence_length,
                    )
                )

        if self._policyEnabled(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_FORBID_REPEATED
        ):
            repeat_limit = self._policyInt(
                oenginecons.ConfigEnv.ADMIN_PASSWORD_REPEAT_LIMIT,
                self._DEFAULT_REPEAT_LIMIT,
            )
            if self._hasRepetition(lowered_password, repeat_limit):
                raise RuntimeError(
                    _(
                        'Password must not repeat a character {limit} times '
                        'or repeat a pattern'
                    ).format(
                        limit=repeat_limit,
                    )
                )

    @plugin.event(
        stage=plugin.Stages.STAGE_BOOT,
    )
    def _boot(self):
        self.environment.setdefault(
            oengcommcons.KeycloakEnv.SUPPORTED,
            False
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_USER_AUTHZ_NAME,
            'internal-authz'
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_USER_AUTHZ_TYPE,
            None
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_USER,
            'admin@internal'
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_USER_NAMESPACE,
            '*'
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_USER_ID,
            None
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_PASSWORD,
            None
        )
        self.environment.setdefault(
            oengcommcons.KeycloakEnv.ENABLE,
            False
        )
        # Password policy. The mandatory checks are on by default, each optional
        # check can be turned off through the answer file.
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_MIN_LENGTH,
            self._MIN_ADMIN_PASSWORD_LENGTH
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_REQUIRE_UPPERCASE,
            True
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_REQUIRE_LOWERCASE,
            True
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_REQUIRE_DIGIT,
            True
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_REQUIRE_SPECIAL,
            True
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_FORBID_SAME_AS_USER_ID,
            True
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_FORBID_REPEATED,
            True
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_REPEAT_LIMIT,
            self._DEFAULT_REPEAT_LIMIT
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_FORBID_SEQUENTIAL,
            True
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_SEQUENCE_LENGTH,
            self._DEFAULT_SEQUENCE_LENGTH
        )
        self.environment.setdefault(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_FORBID_COMMON_WORDS,
            True
        )
        # Bootstrap passwords are temporary by design. Do not allow an answer
        # file to bypass the mandatory first-login credential change.
        self.environment[
            oenginecons.ConfigEnv.ADMIN_PASSWORD_FORCE_CHANGE_ON_FIRST_LOGIN
        ] = True

    @plugin.event(
        stage=plugin.Stages.STAGE_SETUP,
        condition=lambda self: not self.environment[
            oengcommcons.KeycloakEnv.SUPPORTED
        ],
    )
    def _setup(self):
        self.environment[oengcommcons.KeycloakEnv.ENABLE] = False

    @plugin.event(
        stage=plugin.Stages.STAGE_CUSTOMIZATION,
        name=oengcommcons.Stages.ADMIN_PASSWORD_SET,
        before=(
            oengcommcons.Stages.DIALOG_TITLES_E_ENGINE,
        ),
        after=(
            oengcommcons.Stages.DIALOG_TITLES_S_ENGINE,
        ),
        condition=lambda self: (
            self.environment[
                oenginecons.CoreEnv.ENABLE
            ] and self.environment[
                oenginecons.EngineDBEnv.NEW_DATABASE
            ] and self.environment[
                oenginecons.ConfigEnv.ADMIN_PASSWORD
            ] is None
        ),
    )
    def _customization(self):
        valid = False
        password = None
        self.logger.info(
            _(
                '비밀번호 정책: 최소 {minimum}자 이상으로 설정하고, '
                '영문 대/소문자, 숫자, 특수문자를 조합하며, '
                '계정명과 동일한 비밀번호, 사전 단어, '
                '{sequence}자리 연속 문자열 및 반복 문자를 피하십시오.'
            ).format(
                minimum=self._policyInt(
                    oenginecons.ConfigEnv.ADMIN_PASSWORD_MIN_LENGTH,
                    self._MIN_ADMIN_PASSWORD_LENGTH,
                ),
                sequence=self._policyInt(
                    oenginecons.ConfigEnv.ADMIN_PASSWORD_SEQUENCE_LENGTH,
                    self._DEFAULT_SEQUENCE_LENGTH,
                ),
            )
        )
        if self._policyEnabled(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_FORCE_CHANGE_ON_FIRST_LOGIN
        ):
            self.logger.info(
                _(
                    '이 비밀번호는 만료된 상태로 저장되므로 최초 로그인 시 '
                    '비밀번호 변경 절차를 진행해야 합니다.'
                )
            )
        self.logger.info(
            _(
                '운영 정책 안내: 기존 비밀번호를 재사용하지 말고 '
                '보안 기준에 따라 주기적으로 변경하십시오.'
            )
        )
        while not valid:
            password = self.dialog.queryString(
                name='OVESETUP_CONFIG_ADMIN_SETUP',
                note=_('Engine 관리자 비밀번호: '),
                prompt=True,
                hidden=True,
            )
            password2 = self.dialog.queryString(
                name='OVESETUP_CONFIG_ADMIN_SETUP',
                note=_('Engine 관리자 비밀번호 확인: '),
                prompt=True,
                hidden=True,
            )

            if password != password2:
                self.logger.warning(_('Passwords do not match'))
            else:
                try:
                    self._validateAdminPasswordPolicy(password)
                    if _use_pwquality:
                        pwq = pwquality.PWQSettings()
                        pwq.read_config()
                        pwq.check(password, None, None)
                    valid = True
                except RuntimeError as e:
                    self.logger.warning(
                        _('Password is weak: {error}').format(
                            error=str(e),
                        )
                    )
                    self.logger.warning(
                        _('Please enter a stronger password.')
                    )
                except pwquality.PWQError as e:
                    self.logger.warning(
                        _('Password is weak: {error}').format(
                            error=e.args[1],
                        )
                    )
                    self.logger.warning(
                        _('Please enter a stronger password.')
                    )

        self.environment[
            oenginecons.ConfigEnv.ADMIN_PASSWORD
        ] = password

    @plugin.event(
        stage=plugin.Stages.STAGE_VALIDATION,
        priority=plugin.Stages.PRIORITY_LOW,
        condition=lambda self: (
            self.environment[
                oenginecons.CoreEnv.ENABLE
            ] and
            not self.environment[
                oenginecons.EngineDBEnv.NEW_DATABASE
            ]
        ),
    )
    def _validation_late(self):
        adminPassword = None
        try:
            adminPassword = vdcoption.VdcOption(
                statement=database.Statement(
                    dbenvkeys=oenginecons.Const.ENGINE_DB_ENV_KEYS,
                    environment=self.environment,
                ),
            ).getVdcOption(
                'AdminPassword',
                ownConnection=True,
            )
        except RuntimeError:
            pass

        # we have legacy user. Shouldn't happen anymore, after
        # 3.6 https://gerrit.ovirt.org/q/Ica85b6a
        if adminPassword is not None:
            self.dialog.note(
                text=_(
                    'Old AdminPassword found in vdc_options. This should not '
                    'happen, and is likely a result of a bad past upgrade.\n'
                    'Please contact support.\n'
                    'If you are certain that it is not in use anymore, you '
                    'can remove it with this command:\n'
                    '# /usr/share/ovirt-engine/dbscripts/engine-psql.sh -c '
                    '\\\n'
                    '   "select fn_db_delete_config_value(\'AdminPassword\','
                    '\'general\');"\n'
                    '\nand then try again.\n'
                )
            )
            raise RuntimeError(_('Old AdminPassword found in vdc_options'))

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        name=oenginecons.Stages.CONFIG_AAA_ADMIN_USER_SETUP,
        priority=plugin.Stages.PRIORITY_POST,   # order hint
        after=(
            oengcommcons.Stages.DB_CONNECTION_AVAILABLE,
        ),
        condition=lambda self: (
            self.environment[
                oenginecons.CoreEnv.ENABLE
            ] and
            self.environment[
                oenginecons.EngineDBEnv.NEW_DATABASE
            ]
        ),
    )
    def _misc(self):
        if self.environment[
            oenginecons.ConfigEnv.ADMIN_USER_ID
        ] is None:
            raise RuntimeError(_('Missing admin user id'))

        self.environment[oenginecons.EngineDBEnv.STATEMENT].execute(
            statement="""
                select attach_user_to_role(
                    %(admin_user)s,
                    %(authz_name)s,
                    %(namespace)s,
                    %(admin_user_id)s,
                    'SuperUser'
                )
            """,
            args=dict(
                admin_user=self.environment[
                    oenginecons.ConfigEnv.ADMIN_USER
                ].rsplit('@', 1)[0],
                authz_name=self.environment[
                    oenginecons.ConfigEnv.ADMIN_USER_AUTHZ_NAME
                ],
                namespace=self.environment[
                    oenginecons.ConfigEnv.ADMIN_USER_NAMESPACE
                ],
                admin_user_id=self.environment[
                    oenginecons.ConfigEnv.ADMIN_USER_ID
                ],
            ),
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        after=(
            oengcommcons.Stages.DB_CONNECTION_AVAILABLE,
        ),
        condition=lambda self: (
            self.environment[
                oenginecons.CoreEnv.ENABLE
            ]
        ),
    )
    def _attach_group_to_role(self):
        self.environment[oenginecons.EngineDBEnv.STATEMENT].execute(
            statement="""
                select attach_group_to_role(
                    'ovirt-administrator',
                    'SuperUser'
                )
            """
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
                oenginecons.ConfigEnv.ADMIN_PASSWORD
            ] is not None and
            self.environment[
                oengcommcons.KeycloakEnv.ENABLE
            ] is False
        )
    )
    def _closeup(self):
        self.dialog.note(
            text=_(
                "Please use the user '{user}' and password specified in "
                "order to login"
            ).format(
                user=self.environment[
                    oenginecons.ConfigEnv.ADMIN_USER
                ],
            ),
        )
        if self._policyEnabled(
            oenginecons.ConfigEnv.ADMIN_PASSWORD_FORCE_CHANGE_ON_FIRST_LOGIN
        ):
            self.dialog.note(
                text=_(
                    "The password is expired on purpose: the first login "
                    "redirects to the password change page and a new "
                    "password has to be set before the system can be used"
                ),
            )


# vim: expandtab tabstop=4 shiftwidth=4
