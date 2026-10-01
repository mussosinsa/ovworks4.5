#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#

"""Enabling a systemd timer from a setup plugin."""

import gettext


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


def enable_timer(plugin, timer):
    """Enable and start a systemd timer unit.

    Not through plugin.services: otopi's systemd provider appends
    '.service' to every name it is given, so 'x.timer' becomes
    'x.timer.service', which does not exist. systemctl is called directly.

    A timer that cannot be enabled is reported, not raised: it watches the
    system, and is no reason to leave an installation half finished. The
    command to enable it by hand is logged with the warning.

    @return whether the timer is enabled and running
    """
    systemctl = plugin.command.get('systemctl', optional=True)
    if not systemctl:
        plugin.logger.warning(
            _('Cannot enable {timer}: systemctl was not found').format(
                timer=timer,
            )
        )
        return False
    # The unit files may have been installed in this very transaction.
    plugin.execute(
        args=(systemctl, 'daemon-reload'),
        raiseOnError=False,
    )
    rc, _stdout, stderr = plugin.execute(
        args=(systemctl, 'enable', '--now', timer),
        raiseOnError=False,
    )
    if rc != 0:
        plugin.logger.warning(
            _(
                'Cannot enable {timer}: {error}. '
                'Enable it with: systemctl enable --now {timer}'
            ).format(
                timer=timer,
                error=' '.join(stderr).strip() or rc,
            )
        )
        return False
    return True


# vim: expandtab tabstop=4 shiftwidth=4
