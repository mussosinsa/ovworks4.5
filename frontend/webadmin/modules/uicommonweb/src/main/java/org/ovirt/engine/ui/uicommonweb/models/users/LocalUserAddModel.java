package org.ovirt.engine.ui.uicommonweb.models.users;

import org.ovirt.engine.ui.uicommonweb.models.EntityModel;
import org.ovirt.engine.ui.uicommonweb.models.Model;
import org.ovirt.engine.ui.uicommonweb.validation.IValidation;
import org.ovirt.engine.ui.uicommonweb.validation.NotEmptyValidation;
import org.ovirt.engine.ui.uicommonweb.validation.PasswordPolicyValidation;

public class LocalUserAddModel extends Model {
    private final EntityModel<String> userName = new EntityModel<>();
    private final EntityModel<String> firstName = new EntityModel<>();
    private final EntityModel<String> lastName = new EntityModel<>();
    private final EntityModel<String> password = new EntityModel<>();
    private final EntityModel<String> passwordValidTo = new EntityModel<>();
    private final EntityModel<String> email = new EntityModel<>();
    private boolean editing;

    public LocalUserAddModel() {
        applyMode();
    }

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
        applyMode();
    }

    /**
     * Decides which fields the dialog offers, from the model rather than from the view.
     *
     * <p>Editing changes the name and the mail address; it never sets a password, so the two
     * password fields have no meaning there and are not offered - the password of an existing
     * account is changed through 패스워드 리셋, which runs the full policy including the reuse
     * rules. Adding is the mirror image: it assigns the initial password, and has nowhere to put
     * a mail address.</p>
     *
     * <p>This has to be set on the models. The editor driver applies each model's isAvailable to
     * its widget every time it binds, which happens after the view is told to open, so anything
     * the view hides by itself is made visible again a moment later.</p>
     */
    private void applyMode() {
        password.setIsAvailable(!editing);
        passwordValidTo.setIsAvailable(!editing);
        email.setIsAvailable(editing);
    }

    /**
     * Checks the password against the policy before the dialog is submitted. The engine checks it
     * again in AddLocalUserCommand, which is the authority; this only saves the round trip.
     */
    public boolean validate() {
        userName.validateEntity(new IValidation[] { new NotEmptyValidation() });
        if (!editing) {
            password.validateEntity(new IValidation[] {
                    new NotEmptyValidation(),
                    // The user id is part of the policy, so it has to be read at validation time
                    // rather than when the dialog was built.
                    new PasswordPolicyValidation(userName.getEntity())
            });
        }
        return userName.getIsValid() && (editing || password.getIsValid());
    }
}
