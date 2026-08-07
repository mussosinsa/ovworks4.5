package org.ovirt.engine.core.common.action;

import org.ovirt.engine.core.compat.Guid;

public class UserPasswordResetParameters extends ActionParametersBase {

    private static final long serialVersionUID = 1L;

    private Guid userId;
    private String newPassword;

    public UserPasswordResetParameters() {
    }

    public UserPasswordResetParameters(Guid userId, String newPassword) {
        this.userId = userId;
        this.newPassword = newPassword;
    }

    public Guid getUserId() {
        return userId;
    }

    public void setUserId(Guid userId) {
        this.userId = userId;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
