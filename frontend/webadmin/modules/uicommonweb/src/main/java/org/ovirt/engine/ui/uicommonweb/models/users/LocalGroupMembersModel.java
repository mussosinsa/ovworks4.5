package org.ovirt.engine.ui.uicommonweb.models.users;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.ovirt.engine.ui.uicommonweb.models.Model;
import org.ovirt.engine.ui.uicompat.Event;
import org.ovirt.engine.ui.uicompat.EventArgs;
import org.ovirt.engine.ui.uicompat.EventDefinition;

/**
 * The members of a group of the internal authorization provider, as an administrator changes them:
 * the local users who are not in the group on the left, those who are on the right.
 *
 * <p>Nothing is changed until the dialog is submitted; then the users moved right are added and
 * the users moved left are removed (UpdateLocalGroupMembersCommand), and only those.</p>
 */
public class LocalGroupMembersModel extends Model {

    public static final EventDefinition listsChangedEventDefinition =
            new EventDefinition("ListsChanged", LocalGroupMembersModel.class); //$NON-NLS-1$

    private final Event<EventArgs> listsChangedEvent = new Event<>(listsChangedEventDefinition);

    private String groupName;

    /** Who was in the group when the dialog opened. */
    private final Set<String> original = new TreeSet<>();

    private final Set<String> available = new TreeSet<>();
    private final Set<String> members = new TreeSet<>();

    public Event<EventArgs> getListsChangedEvent() {
        return listsChangedEvent;
    }

    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(String groupName) {
        this.groupName = groupName;
    }

    /**
     * @param localUsers every user of the internal provider
     * @param currentMembers the users the provider says are in the group
     */
    public void load(Collection<String> localUsers, Collection<String> currentMembers) {
        original.clear();
        original.addAll(currentMembers);
        members.clear();
        members.addAll(currentMembers);
        available.clear();
        available.addAll(localUsers);
        available.removeAll(members);
        listsChangedEvent.raise(this, EventArgs.EMPTY);
    }

    public List<String> getAvailable() {
        return Collections.unmodifiableList(new ArrayList<>(available));
    }

    public List<String> getMembers() {
        return Collections.unmodifiableList(new ArrayList<>(members));
    }

    public void moveToMembers(Collection<String> users) {
        move(users, available, members);
    }

    public void moveToAvailable(Collection<String> users) {
        move(users, members, available);
    }

    private void move(Collection<String> users, Set<String> from, Set<String> to) {
        boolean moved = false;
        for (String user : users) {
            if (from.remove(user)) {
                to.add(user);
                moved = true;
            }
        }
        if (moved) {
            setMessage(null);
            listsChangedEvent.raise(this, EventArgs.EMPTY);
        }
    }

    /** @return the users to add to the group: on the right now, and not before */
    public ArrayList<String> getUsersToAdd() {
        Set<String> added = new LinkedHashSet<>(members);
        added.removeAll(original);
        return new ArrayList<>(added);
    }

    /** @return the users to take out of the group: on the right before, and not now */
    public ArrayList<String> getUsersToRemove() {
        Set<String> removed = new LinkedHashSet<>(original);
        removed.removeAll(members);
        return new ArrayList<>(removed);
    }

    public boolean hasChanges() {
        return !getUsersToAdd().isEmpty() || !getUsersToRemove().isEmpty();
    }
}
