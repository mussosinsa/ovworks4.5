package org.ovirt.engine.ui.uicommonweb.models.users;

import org.ovirt.engine.ui.uicommonweb.models.EntityModel;
import org.ovirt.engine.ui.uicommonweb.models.Model;
import org.ovirt.engine.ui.uicommonweb.validation.IValidation;
import org.ovirt.engine.ui.uicommonweb.validation.NotEmptyValidation;
import org.ovirt.engine.ui.uicommonweb.validation.PasswordPolicyValidation;
import org.ovirt.engine.ui.uicompat.ConstantsManager;

/**
 * Client side pre-check of the password policy. It mirrors the mandatory part of the policy
 * so that the obvious mistakes are caught before a round trip; the authoritative check,
 * including the configurable and the reuse rules, runs in ResetUserPasswordCommand.
 */
public class UserPasswordResetModel extends Model {

    private EntityModel<String> password;

    private String loginName;

    public EntityModel<String> getPassword() {
        return password;
    }

    private void setPassword(EntityModel<String> value) {
        password = value;
    }

    /**
     * @param loginName login name of the account whose password is being reset, used by the
     *        "password must not equal the user id" check
     */
    public void setLoginName(String loginName) {
        this.loginName = loginName;
    }

    public String getLoginName() {
        return loginName;
    }

    public UserPasswordResetModel() {
        setPassword(new EntityModel<String>());
        setTitle(ConstantsManager.getInstance().getConstants().resetPasswordTitle());
        setHashName("reset_password"); //$NON-NLS-1$
    }

    public boolean validate() {
        getPassword().validateEntity(new IValidation[] {
                new NotEmptyValidation(),
                new PasswordPolicyValidation(loginName)
        });
        return getPassword().getIsValid();
    }
}
