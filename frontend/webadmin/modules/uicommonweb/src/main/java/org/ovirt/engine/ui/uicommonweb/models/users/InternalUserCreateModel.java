package org.ovirt.engine.ui.uicommonweb.models.users;

import org.ovirt.engine.ui.uicommonweb.models.EntityModel;
import org.ovirt.engine.ui.uicommonweb.models.Model;
import org.ovirt.engine.ui.uicommonweb.validation.IValidation;
import org.ovirt.engine.ui.uicommonweb.validation.NotEmptyValidation;

public class InternalUserCreateModel extends Model {
    private EntityModel<String> username = new EntityModel<>();
    private EntityModel<String> firstName = new EntityModel<>();
    private EntityModel<String> lastName = new EntityModel<>();
    private EntityModel<String> password = new EntityModel<>();
    private EntityModel<String> passwordValidTo = new EntityModel<>("");

    public EntityModel<String> getUsername() {
        return username;
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

    public boolean validate() {
        username.validateEntity(new IValidation[] { new NotEmptyValidation() });
        password.validateEntity(new IValidation[] { new NotEmptyValidation() });
        return username.getIsValid() && password.getIsValid();
    }
}
