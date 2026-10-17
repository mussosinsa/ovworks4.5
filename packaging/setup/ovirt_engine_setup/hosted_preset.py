#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright 새올정보기술 (OV-Works), 2026
# SPDX-License-Identifier: Apache-2.0
#


"""The answers a hosted-engine deployment gives engine-setup ahead of time.

A hosted-engine deployment runs engine-setup inside the engine VM with nobody at the keyboard,
but two answers are never taken from an answer file: the KEK passphrase and the PostgreSQL
superuser password. For that deployment they are put in /etc/ovirt-engine/develop.txt:

    Flag=hosted
    KEK=<KEK passphrase>
    Postgres=<PostgreSQL superuser password>

They are used only when Flag is 'hosted'. The file holds passwords in plain text, so it is read
only when it is a regular file owned by root that no one else can read or write (mode 0600 or
stricter); otherwise engine-setup stops and says why rather than use it or ask. Keys are not
case sensitive; a value is what follows the first '=' on its line, without surrounding blanks.
"""


import gettext
import os
import stat


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


PATH = '/etc/ovirt-engine/develop.txt'
HOSTED = 'hosted'


class Preset(object):

    def __init__(self, kek=None, postgres=None):
        self.kek = kek
        self.postgres = postgres


def parse(text):
    """@return the keys and values of the file, keys in lower case"""
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        values[key.strip().lower()] = value.strip()
    return values


def check_owner_and_mode(path, status):
    if not stat.S_ISREG(status.st_mode):
        raise RuntimeError(_('{path} is not a regular file').format(path=path))
    if status.st_uid != 0:
        raise RuntimeError(
            _('{path} holds passwords and must be owned by root (chown root:root {path})').format(
                path=path,
            )
        )
    if stat.S_IMODE(status.st_mode) & 0o077:
        raise RuntimeError(
            _('{path} holds passwords and must not be readable by anyone but root '
              '(chmod 600 {path})').format(path=path)
        )


def read(path=PATH):
    """@return the preset when the file says Flag=hosted, None when there is none to use"""
    try:
        # Not through a symbolic link, and the checks are of the file that is read.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RuntimeError(_('{path} cannot be read: {error}').format(path=path, error=error))
    with os.fdopen(fd, encoding='utf-8') as stream:
        status = os.fstat(stream.fileno())
        values = parse(stream.read())
    if values.get('flag', '').lower() != HOSTED:
        return None
    # Only now: a file that is not for a hosted deployment is not ours to judge.
    check_owner_and_mode(path, status)
    return Preset(
        kek=values.get('kek') or None,
        postgres=values.get('postgres') or None,
    )


# vim: expandtab tabstop=4 shiftwidth=4
