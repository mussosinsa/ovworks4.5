/*
 * Copyright 새올정보기술 (OV-Works), 2026
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.ui.uicommonweb.models.users;

import org.ovirt.engine.core.common.businessentities.BusinessEntitiesDefinitions;
import org.ovirt.engine.ui.uicommonweb.models.EntityModel;
import org.ovirt.engine.ui.uicommonweb.models.Model;
import org.ovirt.engine.ui.uicommonweb.validation.IValidation;
import org.ovirt.engine.ui.uicommonweb.validation.Ipv4AddressValidation;
import org.ovirt.engine.ui.uicommonweb.validation.LengthValidation;
import org.ovirt.engine.ui.uicommonweb.validation.NotEmptyValidation;
import org.ovirt.engine.ui.uicommonweb.validation.PasswordPolicyValidation;
import org.ovirt.engine.ui.uicommonweb.validation.RegexValidation;

public class LocalUserAddModel extends Model {
    private final EntityModel<String> userName = new EntityModel<>();
    private final EntityModel<String> firstName = new EntityModel<>();
    private final EntityModel<String> lastName = new EntityModel<>();
    private final EntityModel<String> password = new EntityModel<>();
    private final EntityModel<String> passwordValidTo = new EntityModel<>();
    private final EntityModel<String> email = new EntityModel<>();
    /**
     * The one address this user may log in from. Registered at creation and changed on edit; an
     * empty value removes the restriction. Enforced by the engine at login (CreateUserSessionCommand).
     */
    private final EntityModel<String> dedicatedIp = new EntityModel<>();
    /**
     * The terminal serial this user logs in with (administrators use config.json's): "ovworks" and a
     * serial number, 12 to 16 characters. Kept encrypted under the DEK and never shown again: on
     * edit the field starts empty, and a value given replaces the registered serial. Enforced by the
     * engine at login (CreateUserSessionCommand).
     */
    private final EntityModel<String> clientSerial = new EntityModel<>();
    /** On edit: whether a serial is registered for the user. Shown, not edited. */
    private final EntityModel<String> clientSerialStatus = new EntityModel<>();
    /** On edit: remove the registered serial. */
    private final EntityModel<Boolean> clearClientSerial = new EntityModel<>(false);
    /**
     * Whether the new account is given the default roles and the default group
     * (ENGINE_LOCAL_USER_DEFAULT_ROLES / _GROUP). Checked by default; adding only.
     */
    private final EntityModel<Boolean> giveDefaults = new EntityModel<>(true);
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

    public EntityModel<String> getDedicatedIp() {
        return dedicatedIp;
    }

    public EntityModel<String> getClientSerial() {
        return clientSerial;
    }

    public EntityModel<String> getClientSerialStatus() {
        return clientSerialStatus;
    }

    public EntityModel<Boolean> getClearClientSerial() {
        return clearClientSerial;
    }

    public EntityModel<Boolean> getGiveDefaults() {
        return giveDefaults;
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
     * <p>Editing changes the name; it never sets a password, so the two password fields have no
     * meaning there and are not offered - the password of an existing account is changed through
     * 패스워드 리셋, which runs the full policy including the reuse rules. Adding is the mirror
     * image: it assigns the initial password. The mail address is offered in neither.</p>
     *
     * <p>This has to be set on the models. The editor driver applies each model's isAvailable to
     * its widget every time it binds, which happens after the view is told to open, so anything
     * the view hides by itself is made visible again a moment later.</p>
     */
    private void applyMode() {
        password.setIsAvailable(!editing);
        passwordValidTo.setIsAvailable(!editing);
        // Not offered in either dialog; on edit the address loaded with the user is sent back as it was.
        email.setIsAvailable(false);
        giveDefaults.setIsAvailable(!editing);
        clientSerialStatus.setIsAvailable(editing);
        clientSerialStatus.setIsChangeable(false);
        clearClientSerial.setIsAvailable(editing);
    }

    /**
     * Checks the password against the policy before the dialog is submitted. The engine checks it
     * again in AddLocalUserCommand, which is the authority; this only saves the round trip.
     */
    public boolean validate() {
        // The login page takes at most this many characters; an ID, a name or a password longer
        // than that would make an account nobody could log in with.
        int max = BusinessEntitiesDefinitions.LOCAL_USER_INPUT_MAX_LENGTH;
        userName.validateEntity(new IValidation[] { new NotEmptyValidation(), new LengthValidation(max) });
        firstName.validateEntity(new IValidation[] { new LengthValidation(max) });
        lastName.validateEntity(new IValidation[] { new LengthValidation(max) });
        if (!editing) {
            password.validateEntity(new IValidation[] {
                    new NotEmptyValidation(),
                    new LengthValidation(max),
                    // The user id is part of the policy, so it has to be read at validation time
                    // rather than when the dialog was built.
                    new PasswordPolicyValidation(userName.getEntity())
            });
        }
        // A dedicated login IP is optional in the dialog, but when given it must be a single IPv4
        // address: it is also registered as a terminal IP, which takes nothing else. Empty is
        // allowed and removes the restriction.
        if (dedicatedIp.getEntity() != null && !dedicatedIp.getEntity().trim().isEmpty()) {
            dedicatedIp.validateEntity(new IValidation[] { new Ipv4AddressValidation() });
        } else {
            dedicatedIp.setIsValid(true);
        }
        // The security rules: "ovworks" and the serial number, 12 to 16 characters. The engine
        // checks it again.
        if (clientSerial.getEntity() != null && !clientSerial.getEntity().trim().isEmpty()) {
            RegexValidation serialFormat = new RegexValidation();
            serialFormat.setExpression("^ovworks[0-9]{5,9}$"); //$NON-NLS-1$
            serialFormat.setMessage("ovworks 다음에 숫자(일련번호)를 붙여 12~16자로 입력하십시오. 예: ovworks00001"); //$NON-NLS-1$
            clientSerial.validateEntity(new IValidation[] { serialFormat });
        } else {
            clientSerial.setIsValid(true);
        }
        return userName.getIsValid() && firstName.getIsValid() && lastName.getIsValid()
                && dedicatedIp.getIsValid() && clientSerial.getIsValid()
                && (editing || password.getIsValid());
    }
}
