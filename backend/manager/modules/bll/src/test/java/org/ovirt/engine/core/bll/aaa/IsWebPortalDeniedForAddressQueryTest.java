package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.bll.SetUserDedicatedIpCommand;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;
import org.ovirt.engine.core.compat.Guid;

class IsWebPortalDeniedForAddressQueryTest {

    private static final Guid USER = new Guid("aaaaaaaa-0000-0000-0000-000000000001");
    private static final Guid OTHER_USER = new Guid("bbbbbbbb-0000-0000-0000-000000000002");
    private static final Guid ADMIN = new Guid("cccccccc-0000-0000-0000-000000000003");

    private static final List<UserProfileProperty> PROPERTIES = List.of(
            dedicatedIp(USER, "192.168.40.92"),
            dedicatedIp(OTHER_USER, "192.168.40.92"),
            dedicatedIp(ADMIN, "192.168.40.10"));

    @Test
    void theUsersOfAnAddressAreFoundByTheirDedicatedIp() {
        assertEquals(List.of(USER, OTHER_USER),
                IsWebPortalDeniedForAddressQuery.usersWithDedicatedIp(PROPERTIES, "192.168.40.92"));
        assertTrue(IsWebPortalDeniedForAddressQuery.usersWithDedicatedIp(PROPERTIES, "192.168.40.50").isEmpty());
    }

    @Test
    void anAddressOnlyUsersHaveDoesNotGetThePortal() {
        assertTrue(IsWebPortalDeniedForAddressQuery.isDenied(List.of(USER, OTHER_USER), Set.of(ADMIN)::contains));
    }

    @Test
    void anAdministratorsAddressKeepsThePortal() {
        assertFalse(IsWebPortalDeniedForAddressQuery.isDenied(List.of(ADMIN), Set.of(ADMIN)::contains));
        // Shared with an administrator: refusing it would lock the administrator out.
        assertFalse(IsWebPortalDeniedForAddressQuery.isDenied(List.of(USER, ADMIN), Set.of(ADMIN)::contains));
    }

    @Test
    void anAddressNobodyHasAsADedicatedIpIsLeftToTheTerminalList() {
        assertFalse(IsWebPortalDeniedForAddressQuery.isDenied(List.of(), Set.of(ADMIN)::contains));
    }

    private static UserProfileProperty dedicatedIp(Guid userId, String ip) {
        return UserProfileProperty.builder()
                .withUserId(userId)
                .withName(SetUserDedicatedIpCommand.DEDICATED_LOGIN_IP_PROPERTY)
                .withTypeJson()
                .withContent("\"" + ip + "\"") //$NON-NLS-1$ //$NON-NLS-2$
                .build();
    }
}
