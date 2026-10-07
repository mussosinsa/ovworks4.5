package org.ovirt.engine.core.common.action;

import java.util.ArrayList;
import java.util.List;

/**
 * The users to add to a group of the internal authorization provider, and the users to remove from it.
 */
public class UpdateLocalGroupMembersParameters extends ActionParametersBase {

    private static final long serialVersionUID = 3409168211583826751L;

    private String groupName;
    private ArrayList<String> usersToAdd = new ArrayList<>();
    private ArrayList<String> usersToRemove = new ArrayList<>();

    public UpdateLocalGroupMembersParameters() {
    }

    public UpdateLocalGroupMembersParameters(String groupName, List<String> usersToAdd, List<String> usersToRemove) {
        this.groupName = groupName;
        if (usersToAdd != null) {
            this.usersToAdd = new ArrayList<>(usersToAdd);
        }
        if (usersToRemove != null) {
            this.usersToRemove = new ArrayList<>(usersToRemove);
        }
    }

    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(String groupName) {
        this.groupName = groupName;
    }

    public List<String> getUsersToAdd() {
        return usersToAdd;
    }

    public void setUsersToAdd(ArrayList<String> usersToAdd) {
        this.usersToAdd = usersToAdd;
    }

    public List<String> getUsersToRemove() {
        return usersToRemove;
    }

    public void setUsersToRemove(ArrayList<String> usersToRemove) {
        this.usersToRemove = usersToRemove;
    }
}
