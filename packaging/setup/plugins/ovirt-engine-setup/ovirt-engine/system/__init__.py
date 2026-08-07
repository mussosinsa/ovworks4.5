#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""ovirt-host-setup system plugin."""


from otopi import util

from . import acl
from . import engine
from . import memcheck
from . import security_audit


@util.export
def createPlugins(context):
    acl.Plugin(context=context)
    engine.Plugin(context=context)
    memcheck.Plugin(context=context)
    security_audit.Plugin(context=context)


# vim: expandtab tabstop=4 shiftwidth=4
