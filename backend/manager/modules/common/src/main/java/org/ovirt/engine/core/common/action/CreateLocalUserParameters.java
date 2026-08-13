package org.ovirt.engine.core.common.action;

public class CreateLocalUserParameters extends ActionParametersBase {

    private static final long serialVersionUID = 1L;

    private String username;
    private String firstName;
    private String lastName;
    private String password;
    private String passwordValidTo;

    public CreateLocalUserParameters() {
    }

    public CreateLocalUserParameters(String username, String firstName, String lastName,
            String password, String passwordValidTo) {
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.password = password;
        this.passwordValidTo = passwordValidTo;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPasswordValidTo() {
        return passwordValidTo;
    }

    public void setPasswordValidTo(String passwordValidTo) {
        this.passwordValidTo = passwordValidTo;
    }
}
