# Modified by 새올정보기술 for OV-Works (2026). Changes against oVirt Engine 4.5.6: docs/ovworks-source-change-statement.md
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
from . import audit_storage_watch
from . import dwh_scram_runtime
from . import engine
from . import integrity_baseline
from . import memcheck
from . import security_audit


@util.export
def createPlugins(context):
    acl.Plugin(context=context)
    audit_storage_watch.Plugin(context=context)
    dwh_scram_runtime.Plugin(context=context)
    engine.Plugin(context=context)
    integrity_baseline.Plugin(context=context)
    memcheck.Plugin(context=context)
    security_audit.Plugin(context=context)


# vim: expandtab tabstop=4 shiftwidth=4
