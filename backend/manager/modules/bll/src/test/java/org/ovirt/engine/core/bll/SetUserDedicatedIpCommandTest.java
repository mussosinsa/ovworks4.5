package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;
import org.ovirt.engine.core.compat.Guid;

class SetUserDedicatedIpCommandTest {

    private static final Guid USER_A = new Guid("aaaaaaaa-0000-0000-0000-000000000001");
    private static final Guid USER_B = new Guid("bbbbbbbb-0000-0000-0000-000000000002");

    @Test
    void aSingleIpv4AddressIsAccepted() {
        assertTrue(SetUserDedicatedIpCommand.isAcceptableAddress("192.168.40.10"));
    }

    @Test
    void whatTheTerminalListRefusesIsRefusedHereToo() {
        // The address also goes on the terminal IP list, which takes one IPv4 address and nothing else.
        assertFalse(SetUserDedicatedIpCommand.isAcceptableAddress("192.168.40.0/24"));
        assertFalse(SetUserDedicatedIpCommand.isAcceptableAddress("fe80::1"));
        assertFalse(SetUserDedicatedIpCommand.isAcceptableAddress("0.0.0.0"));
        assertFalse(SetUserDedicatedIpCommand.isAcceptableAddress("255.255.255.255"));
        assertFalse(SetUserDedicatedIpCommand.isAcceptableAddress("host.example.com"));
    }

    @Test
    void anAddressAnotherUserHasIsKeptOnTheTerminalList() {
        List<UserProfileProperty> properties = List.of(dedicatedIp(USER_A, "192.168.40.10"),
                dedicatedIp(USER_B, "192.168.40.10"));
        assertTrue(SetUserDedicatedIpCommand.isUsedByAnotherUser(properties, USER_A, "192.168.40.10"));
    }

    @Test
    void anAddressOnlyThisUserHasMayBeRemoved() {
        List<UserProfileProperty> properties = List.of(dedicatedIp(USER_A, "192.168.40.10"),
                dedicatedIp(USER_B, "192.168.40.20"));
        assertFalse(SetUserDedicatedIpCommand.isUsedByAnotherUser(properties, USER_A, "192.168.40.10"));
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
