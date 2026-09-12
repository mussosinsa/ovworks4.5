package org.ovirt.engine.core.common.action;

public class AddLocalGroupParameters extends ActionParametersBase {

    private static final long serialVersionUID = 7742297741166295411L;

    private String groupName;

    public AddLocalGroupParameters() {
    }

    public AddLocalGroupParameters(String groupName) {
        this.groupName = groupName;
    }

    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(String groupName) {
        this.groupName = groupName;
    }
}
