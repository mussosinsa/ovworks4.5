package org.ovirt.engine.ui.uicommonweb.models.users;

import org.ovirt.engine.ui.uicommonweb.ICommandTarget;
import org.ovirt.engine.ui.uicommonweb.UICommand;
import org.ovirt.engine.ui.uicommonweb.models.EntityModel;
import org.ovirt.engine.ui.uicommonweb.models.Model;
import org.ovirt.engine.ui.uicommonweb.validation.IValidation;
import org.ovirt.engine.ui.uicommonweb.validation.NotEmptyValidation;
import org.ovirt.engine.ui.uicommonweb.validation.RegexValidation;
import org.ovirt.engine.ui.uicommonweb.validation.ValidationResult;

public class LocalUserModel extends Model {

    private static final int MIN_PASSWORD_LENGTH = 6;
    private static final String MIN_LENGTH_REGEX = "^.{" + MIN_PASSWORD_LENGTH + ",}$"; //$NON-NLS-1$ //$NON-NLS-2$

    private final EntityModel<String> username = new EntityModel<>();
    private final EntityModel<String> firstName = new EntityModel<>();
    private final EntityModel<String> lastName = new EntityModel<>();
    private final EntityModel<String> password = new EntityModel<>();
    private final EntityModel<String> passwordValidTo = new EntityModel<>();

    public LocalUserModel() {
        passwordValidTo.setEntity(""); //$NON-NLS-1$
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
        password.validateEntity(new IValidation[] {
                new NotEmptyValidation(),
                new RegexValidation(MIN_LENGTH_REGEX, "패스워드는 최소 6자리 이상이어야 합니다."), //$NON-NLS-1$
                value -> username.getEntity() != null && value instanceof String
                        && username.getEntity().equalsIgnoreCase((String) value)
                        ? ValidationResult.fail("사용자 계정과 동일한 패스워드는 사용할 수 없습니다.") //$NON-NLS-1$
                        : ValidationResult.ok()
        });
        return username.getIsValid() && firstName.getIsValid() && lastName.getIsValid()
                && password.getIsValid();
    }
}
