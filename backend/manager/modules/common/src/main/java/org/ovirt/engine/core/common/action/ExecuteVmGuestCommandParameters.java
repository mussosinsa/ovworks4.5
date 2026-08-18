package org.ovirt.engine.core.common.action;

import org.ovirt.engine.core.compat.Guid;

/** Parameters for executing an approved script through the QEMU guest agent. */
public class ExecuteVmGuestCommandParameters extends VmOperationParameterBase {
    private String path;

    public ExecuteVmGuestCommandParameters() {
    }

    public ExecuteVmGuestCommandParameters(Guid vmId, String path) {
        super(vmId);
        this.path = path;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }
}
