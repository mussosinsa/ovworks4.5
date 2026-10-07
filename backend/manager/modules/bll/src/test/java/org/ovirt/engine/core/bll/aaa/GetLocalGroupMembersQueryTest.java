package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

/** The members are read out of what {@code ovirt-aaa-jdbc-tool group-manage show} prints. */
class GetLocalGroupMembersQueryTest {

    @Test
    void readsTheUsersAndNotTheMemberGroupsOrTheHeading() {
        String output = "Group: ops(6be45bbc-ad97-11f1-9f56-566f0a1b2c3d) members:\n"
                + "  User: user01\n"
                + "  User: user.02\n"
                + "  Group: nested\n";
        assertEquals(Arrays.asList("user01", "user.02"), GetLocalGroupMembersQuery.membersIn(output));
    }

    @Test
    void aGroupWithNoMembersHasNone() {
        assertTrue(GetLocalGroupMembersQuery.membersIn(
                "Group: ops(6be45bbc-ad97-11f1-9f56-566f0a1b2c3d) has no members.").isEmpty());
        assertTrue(GetLocalGroupMembersQuery.membersIn(null).isEmpty());
    }
}
