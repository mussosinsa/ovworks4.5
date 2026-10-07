package org.ovirt.engine.core.bll;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.ChangePermissionRoleParameters;
import org.ovirt.engine.core.common.businessentities.Permission;
import org.ovirt.engine.core.common.businessentities.Role;
import org.ovirt.engine.core.common.businessentities.RoleType;
import org.ovirt.engine.core.common.businessentities.VM;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.PermissionDao;
import org.ovirt.engine.core.dao.RoleDao;
import org.ovirt.engine.core.dao.VmDao;
import org.ovirt.engine.core.dao.VmStaticDao;
import org.ovirt.engine.core.utils.transaction.TransactionSupport;

/**
 * Gives a permission on a virtual machine another role: the same user or group, on the same
 * virtual machine.
 *
 * <p>Changing a role used to mean removing the permission and adding a new one, two actions with a
 * moment between them in which the user or group had no access to the machine at all - and, if
 * the second failed, kept none. The old permission is replaced by the new one in one transaction
 * here, so it is one or the other, and the change is one record in the audit log.</p>
 */
public class ChangePermissionRoleCommand<T extends ChangePermissionRoleParameters> extends PermissionsCommandBase<T> {

    @Inject
    private PermissionDao permissionDao;
    @Inject
    private RoleDao roleDao;
    @Inject
    private VmDao vmDao;
    @Inject
    private VmStaticDao vmStaticDao;

    private Permission current;
    private Role newRole;

    public ChangePermissionRoleCommand(T parameters, CommandContext commandContext) {
        super(parameters, commandContext);
    }

    /** The permission as it is stored, not as the caller described it. */
    private Permission current() {
        if (current == null && getParameters().getPermission() != null
                && !Guid.isNullOrEmpty(getParameters().getPermission().getId())) {
            current = permissionDao.get(getParameters().getPermission().getId());
            if (current != null) {
                getParameters().setPermission(current);
            }
        }
        return current;
    }

    @Override
    protected boolean validate() {
        Permission permission = current();
        if (permission == null) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_PERMISSION_NOT_FOUND);
        }
        if (permission.getObjectType() != VdcObjectType.VM) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_PERMISSION_ROLE_CHANGE_VM_ONLY);
        }
        newRole = Guid.isNullOrEmpty(getParameters().getNewRoleId())
                ? null
                : roleDao.get(getParameters().getNewRoleId());
        if (newRole == null) {
            return failValidation(EngineMessage.PERMISSION_ADD_FAILED_INVALID_ROLE_ID);
        }
        addCustomValue("NewRoleName", newRole.getName()); //$NON-NLS-1$
        if (newRole.getId().equals(permission.getRoleId())) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_PERMISSION_ROLE_UNCHANGED);
        }
        // As AddPermissionCommand: only the system super user gives administrator roles, and a
        // virtual machine of a pool is given its users through the pool.
        if (!isSystemSuperUser() && newRole.getType() == RoleType.ADMIN) {
            return failValidation(EngineMessage.PERMISSION_ADD_FAILED_ONLY_SYSTEM_SUPER_USER_CAN_GIVE_ADMIN_ROLES);
        }
        VM vm = vmDao.get(permission.getObjectId());
        if (vm != null && vm.getVmPoolId() != null) {
            return failValidation(EngineMessage.PERMISSION_ADD_FAILED_VM_IN_POOL);
        }
        return true;
    }

    @Override
    protected void executeCommand() {
        Permission old = current();
        Permission existing = permissionDao.getForRoleAndAdElementAndObject(
                newRole.getId(), old.getAdElementId(), old.getObjectId());
        Permission replacement = existing != null
                ? existing
                : new Permission(old.getAdElementId(), newRole.getId(), old.getObjectId(), old.getObjectType());
        TransactionSupport.executeInNewTransaction(() -> {
            permissionDao.remove(old.getId());
            if (existing == null) {
                permissionDao.save(replacement);
            }
            return null;
        });
        vmStaticDao.incrementDbGeneration(old.getObjectId());
        getReturnValue().setActionReturnValue(replacement.getId());
        setSucceeded(true);
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return getSucceeded() ? AuditLogType.PERMISSION_ROLE_CHANGED : AuditLogType.PERMISSION_ROLE_CHANGE_FAILED;
    }
}
