package org.ovirt.engine.ui.uicommonweb.models.users;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.ovirt.engine.core.common.businessentities.Permission;
import org.ovirt.engine.core.common.businessentities.Role;
import org.ovirt.engine.core.common.businessentities.VM;
import org.ovirt.engine.ui.uicommonweb.models.ListModel;
import org.ovirt.engine.ui.uicommonweb.models.Model;
import org.ovirt.engine.ui.uicommonweb.validation.IValidation;
import org.ovirt.engine.ui.uicommonweb.validation.NotEmptyValidation;

/**
 * A virtual machine and a role, given to a user or a group (AddPermission), or a new role for a
 * permission it already has on a virtual machine (ChangePermissionRole).
 *
 * <p>When a role is changed the machine is the one the permission is on and cannot be changed:
 * a permission on another machine is another permission, given with the assignment instead.</p>
 */
public class VmPermissionModel extends Model {

    private final ListModel<VM> vm = new ListModel<>();
    private final ListModel<Role> role = new ListModel<>();

    /** The permission whose role is being changed; null when a machine is being given. */
    private Permission changing;

    public ListModel<VM> getVm() {
        return vm;
    }

    public ListModel<Role> getRole() {
        return role;
    }

    public Permission getChanging() {
        return changing;
    }

    public boolean isChangingRole() {
        return changing != null;
    }

    /** Fixes the machine to the one the permission is on, and starts from its current role. */
    public void setChanging(Permission permission) {
        this.changing = permission;
        VM fixed = new VM();
        fixed.setId(permission.getObjectId());
        fixed.setName(permission.getObjectName());
        List<VM> only = new ArrayList<>();
        only.add(fixed);
        vm.setItems(only);
        vm.setSelectedItem(fixed);
        vm.setIsChangeable(false);
    }

    /**
     * @param vms every virtual machine the administrator can see; those of a pool are left out,
     *            a pool's machines being given to users through the pool (AddPermissionCommand
     *            refuses them)
     */
    public void setVms(List<VM> vms) {
        List<VM> assignable = new ArrayList<>();
        for (VM candidate : vms) {
            if (candidate.getVmPoolId() == null) {
                assignable.add(candidate);
            }
        }
        assignable.sort(Comparator.comparing(VM::getName, String.CASE_INSENSITIVE_ORDER));
        vm.setItems(assignable);
        vm.setSelectedItem(assignable.isEmpty() ? null : assignable.get(0));
    }

    public void setRoles(List<Role> roles) {
        List<Role> sorted = new ArrayList<>(roles);
        sorted.sort(Comparator.comparing(Role::getName, String.CASE_INSENSITIVE_ORDER));
        role.setItems(sorted);
        Role current = null;
        if (changing != null) {
            for (Role candidate : sorted) {
                if (candidate.getId().equals(changing.getRoleId())) {
                    current = candidate;
                }
            }
        }
        role.setSelectedItem(current != null ? current : sorted.isEmpty() ? null : sorted.get(0));
    }

    public boolean validate() {
        vm.validateSelectedItem(new IValidation[] { new NotEmptyValidation() });
        role.validateSelectedItem(new IValidation[] { new NotEmptyValidation() });
        if (vm.getIsValid() && role.getIsValid() && changing != null
                && role.getSelectedItem().getId().equals(changing.getRoleId())) {
            setMessage("현재와 같은 역할입니다. 다른 역할을 고르세요."); //$NON-NLS-1$
            return false;
        }
        return vm.getIsValid() && role.getIsValid();
    }
}
