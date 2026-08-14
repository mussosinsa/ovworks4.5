package org.ovirt.engine.core.common.utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class Ipv4AddressUtilsTest {

    @Test
    void acceptsSingleIpv4AddressesUsedByTerminalAuthentication() {
        assertTrue(Ipv4AddressUtils.isValidAddress("192.168.10.111")); //$NON-NLS-1$
        assertTrue(Ipv4AddressUtils.isValidAddress("192.168.40.86")); //$NON-NLS-1$
        assertTrue(Ipv4AddressUtils.isValidAddress("127.0.0.1")); //$NON-NLS-1$
    }

    @Test
    void rejectsRangesDirectivesAndInvalidOctets() {
        assertFalse(Ipv4AddressUtils.isValidAddress("192.168.10.0/24")); //$NON-NLS-1$
        assertFalse(Ipv4AddressUtils.isValidAddress("Require ip 192.168.10.111")); //$NON-NLS-1$
        assertFalse(Ipv4AddressUtils.isValidAddress("192.168.10.256")); //$NON-NLS-1$
        assertFalse(Ipv4AddressUtils.isValidAddress("192.168.10")); //$NON-NLS-1$
    }
}
