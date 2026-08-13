package org.ovirt.engine.core.common.action;

public class AddLocalUserParameters extends ActionParametersBase {
    private String userName;
    private String firstName;
    private String lastName;
    private String password;
    private String passwordValidTo;

    public AddLocalUserParameters() {
    }

    public AddLocalUserParameters(String userName, String firstName, String lastName,
            String password, String passwordValidTo) {
        this.userName = userName;
        this.firstName = firstName;
        this.lastName = lastName;
        this.password = password;
        this.passwordValidTo = passwordValidTo;
    }

    public String getUserName() { return userName; }
    public void setUserName(String userName) { this.userName = userName; }
    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getPasswordValidTo() { return passwordValidTo; }
    public void setPasswordValidTo(String passwordValidTo) { this.passwordValidTo = passwordValidTo; }
}
