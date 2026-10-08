package org.ovirt.engine.core.common.action;

public class AddLocalUserParameters extends ActionParametersBase {
    private String userName;
    private String firstName;
    private String lastName;
    private String password;
    private String passwordValidTo;
    /**
     * Whether the user is given what every new local user is given (the default roles and the
     * default group). On unless the administrator turns it off for this account.
     */
    private boolean giveDefaults = true;

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

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
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

    public boolean isGiveDefaults() {
        return giveDefaults;
    }

    public void setGiveDefaults(boolean giveDefaults) {
        this.giveDefaults = giveDefaults;
    }
}
