package org.ovirt.engine.ui.uicommonweb.models.users;

import org.ovirt.engine.ui.uicommonweb.ICommandTarget;
import org.ovirt.engine.ui.uicommonweb.UICommand;
import org.ovirt.engine.ui.uicommonweb.models.EntityModel;
import org.ovirt.engine.ui.uicommonweb.models.Model;
import org.ovirt.engine.ui.uicommonweb.validation.IValidation;
import org.ovirt.engine.ui.uicommonweb.validation.NotEmptyValidation;

public class LocalUserModel extends Model {

    private final EntityModel<String> username = new EntityModel<>();
    private final EntityModel<String> firstName = new EntityModel<>();
    private final EntityModel<String> lastName = new EntityModel<>();
    private final EntityModel<String> password = new EntityModel<>();
    private final EntityModel<String> passwordValidTo = new EntityModel<>();

    public LocalUserModel() {
        passwordValidTo.setEntity("2025-08-01 12:00:00-0800"); //$NON-NLS-1$
    }

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

    public void addCancelCommand(ICommandTarget cancelCommandTarget) {
        getCommands().add(UICommand.createCancelUiCommand("Cancel", cancelCommandTarget)); //$NON-NLS-1$
    }

    public boolean validate() {
        IValidation[] required = { new NotEmptyValidation() };
        username.validateEntity(required);
        firstName.validateEntity(required);
        lastName.validateEntity(required);
        password.validateEntity(required);
        passwordValidTo.validateEntity(required);
        return username.getIsValid() && firstName.getIsValid() && lastName.getIsValid()
                && password.getIsValid() && passwordValidTo.getIsValid();
    }
}
