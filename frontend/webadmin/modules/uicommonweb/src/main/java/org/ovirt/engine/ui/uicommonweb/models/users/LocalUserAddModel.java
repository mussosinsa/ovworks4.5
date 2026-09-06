package org.ovirt.engine.ui.uicommonweb.models.users;

import org.ovirt.engine.ui.uicommonweb.models.EntityModel;
import org.ovirt.engine.ui.uicommonweb.models.Model;
import org.ovirt.engine.ui.uicommonweb.validation.IValidation;
import org.ovirt.engine.ui.uicommonweb.validation.NotEmptyValidation;

public class LocalUserAddModel extends Model {
    private final EntityModel<String> userName = new EntityModel<>();
    private final EntityModel<String> firstName = new EntityModel<>();
    private final EntityModel<String> lastName = new EntityModel<>();
    private final EntityModel<String> password = new EntityModel<>();
    private final EntityModel<String> passwordValidTo = new EntityModel<>();
    private final EntityModel<String> email = new EntityModel<>();
    private boolean editing;

    public EntityModel<String> getUserName() {
        return userName;
    }

    public EntityModel<String> getFirstName() {
        return firstName;
    }

    public EntityModel<String> getLastName() {
        return lastName;
    }

    public EntityModel<String> getPassword() {
        return password;
    }

    public EntityModel<String> getPasswordValidTo() {
        return passwordValidTo;
    }

    public EntityModel<String> getEmail() {
        return email;
    }

    public boolean isEditing() {
        return editing;
    }

    public void setEditing(boolean editing) {
        this.editing = editing;
    }

    public boolean validate() {
        IValidation[] required = { new NotEmptyValidation() };
        userName.validateEntity(required);
        if (!editing) {
            password.validateEntity(required);
        }
        return userName.getIsValid() && (editing || password.getIsValid());
    }
}
