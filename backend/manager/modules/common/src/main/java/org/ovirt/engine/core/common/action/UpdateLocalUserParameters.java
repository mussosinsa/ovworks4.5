package org.ovirt.engine.core.common.action;

import org.ovirt.engine.core.compat.Guid;

public class UpdateLocalUserParameters extends IdParameters {
    private String firstName;
    private String lastName;
    private String email;

    public UpdateLocalUserParameters() {
    }

    public UpdateLocalUserParameters(Guid userId, String firstName, String lastName, String email) {
        super(userId);
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getEmail() {
        return email;
    }
}
