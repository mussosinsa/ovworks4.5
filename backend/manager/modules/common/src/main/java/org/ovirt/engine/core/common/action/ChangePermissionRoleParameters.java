package org.ovirt.engine.core.common.action;

import org.ovirt.engine.core.common.businessentities.Permission;
import org.ovirt.engine.core.compat.Guid;

/**
 * A permission to give another role: the same user or group, on the same object.
 */
public class ChangePermissionRoleParameters extends PermissionsOperationsParameters {

    private static final long serialVersionUID = -5110563820617458113L;

    private Guid newRoleId;

    public ChangePermissionRoleParameters() {
    }

    public ChangePermissionRoleParameters(Permission permission, Guid newRoleId) {
        super(permission);
        this.newRoleId = newRoleId;
    }

    public Guid getNewRoleId() {
        return newRoleId;
    }

    public void setNewRoleId(Guid newRoleId) {
        this.newRoleId = newRoleId;
    }
}
