#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright 새올정보기술 (OV-Works), 2026
# SPDX-License-Identifier: Apache-2.0
#
#


"""The rules the database passwords of engine-setup are made and checked by.

The same rules the administrator's password is held to (config/aaa.py): at
least one upper-case letter, lower-case letter, digit and special character,
not the account name, no character three times in a row or repeated block, no
run of four alphabetical, numerical or keyboard-sequential characters and no
common word. A password engine-setup generates is made to them; one entered by
the administrator for the PostgreSQL superuser is refused unless it follows
them.
"""


import gettext
import re

from ovirt_engine import csprng


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'
DIGITS = '0123456789'

# The special characters a generated password takes: none that needs quoting
# where the password is kept or passed - a double-quoted value of
# engine.conf.d (" $ \ `), .pgpass (: \), an INI file (% for interpolation) or
# a shell - and none the login input policy refuses (| ; : `) or reads as SQL
# syntax (-- /* */).
GENERATED_SPECIALS = '!+,.=?@^_~'

GENERATED_LENGTH = 22

REPEAT_LIMIT = 3
SEQUENCE_LENGTH = 4
_MAX_PATTERN_LENGTH = 4

# As config/aaa.py: both directions of each run are refused.
SEQUENCES = (
    '0123456789',
    'abcdefghijklmnopqrstuvwxyz',
    '`1234567890-=',
    'qwertyuiop[]\\',
    "asdfghjkl;'",
    'zxcvbnm,./',
    '~!@#$%^&*()_+',
)

WEAK_WORDS = (
    'password',
    'admin',
    'ovirt',
    'engine',
    'welcome',
    'qwerty',
    'postgres',
)


def has_repetition(lowered):
    """A character REPEAT_LIMIT times in a row, or a block such as 'abab'."""
    if re.search(r'(.)\1{%d}' % (REPEAT_LIMIT - 1), lowered) is not None:
        return True
    for length in range(2, _MAX_PATTERN_LENGTH + 1):
        for index in range(len(lowered) - 2 * length + 1):
            if lowered[index:index + length] == lowered[
                index + length:index + 2 * length
            ]:
                return True
    return False


def has_sequence(lowered):
    for index in range(len(lowered) - SEQUENCE_LENGTH + 1):
        token = lowered[index:index + SEQUENCE_LENGTH]
        for sequence in SEQUENCES:
            if token in sequence or token[::-1] in sequence:
                return True
    return False


def violation(password, account=None, min_length=12):
    """@return what the password breaks, or None when it follows the rules"""
    if not isinstance(password, str) or len(password) < min_length:
        return _(
            'Password must be at least {length} characters long'
        ).format(length=min_length)
    for pattern, message in (
        (r'[a-z]', _('Password must contain a lowercase letter')),
        (r'[A-Z]', _('Password must contain an uppercase letter')),
        (r'[0-9]', _('Password must contain a digit')),
        (r'[^A-Za-z0-9]', _('Password must contain a special character')),
    ):
        if re.search(pattern, password) is None:
            return message
    lowered = password.lower()
    if account and lowered == account.lower():
        return _('Password must not be identical to the account name')
    for word in WEAK_WORDS:
        if word in lowered:
            return _('Password must not contain common dictionary words')
    if has_sequence(lowered):
        return _(
            'Password must not contain {length} alphabetical, numerical or '
            'keyboard sequential characters'
        ).format(length=SEQUENCE_LENGTH)
    if has_repetition(lowered):
        return _(
            'Password must not repeat a character {limit} times or repeat '
            'a pattern'
        ).format(limit=REPEAT_LIMIT)
    return None


def generate(length=GENERATED_LENGTH):
    """A password of the given length, from the product's CSPRNG, that follows
    the rules: one character of each kind, the rest from all of them, shuffled,
    drawn again in the rare case it makes a run or a repetition."""
    if length < 8:
        raise ValueError('a generated password is at least 8 characters')
    rand = csprng.SystemRandom()
    every = UPPERCASE + LOWERCASE + DIGITS + GENERATED_SPECIALS
    while True:
        characters = [
            rand.choice(UPPERCASE),
            rand.choice(LOWERCASE),
            rand.choice(DIGITS),
            rand.choice(GENERATED_SPECIALS),
        ] + [rand.choice(every) for i in range(length - 4)]
        rand.shuffle(characters)
        password = ''.join(characters)
        if violation(password, min_length=length) is None:
            return password


# vim: expandtab tabstop=4 shiftwidth=4
