package org.ovirt.engine.core.common.action;

public class CreateInternalUserParameters extends ActionParametersBase {
    private String username;
    private String firstName;
    private String lastName;
    private String password;
    private String passwordValidTo;

    public CreateInternalUserParameters() { }

    public CreateInternalUserParameters(String username, String firstName, String lastName,
            String password, String passwordValidTo) {
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.password = password;
        this.passwordValidTo = passwordValidTo;
    }

    public String getUsername() { return username; }
    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
    public String getPassword() { return password; }
    public String getPasswordValidTo() { return passwordValidTo; }
}
