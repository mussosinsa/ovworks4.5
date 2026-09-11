package org.ovirt.engine.core.common.utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Which addresses may stand for a terminal that is allowed to reach the engine.
 */
class Ipv4AddressUtilsTest {

    /* Well formed, and meaning what a list of permitted terminals is for. */

    @Test
    void acceptsASingleTerminal() {
        assertTrue(Ipv4AddressUtils.isUsableTerminalAddress("192.168.40.38"));
        assertTrue(Ipv4AddressUtils.isUsableTerminalAddress("192.168.40.0/32"));
    }

    @Test
    void acceptsARangeOfTerminals() {
        assertTrue(Ipv4AddressUtils.isUsableTerminalAddress("192.168.40.0/24"));
        assertTrue(Ipv4AddressUtils.isUsableTerminalAddress("10.10.3.0/24"));
        assertTrue(Ipv4AddressUtils.isUsableTerminalAddress("10.0.0.0/8"));
    }

    @Test
    void acceptsLoopbackBecauseSetupPutsItThereItself() {
        assertTrue(Ipv4AddressUtils.isUsableTerminalAddress("127.0.0.1"));
        assertTrue(Ipv4AddressUtils.isUsableTerminalAddress("127.0.0.0/8"));
    }

    /* Values that would let every terminal through. */

    @Test
    void refusesWhatMatchesEveryAddress() {
        assertFalse(Ipv4AddressUtils.isUsableTerminalAddress("0.0.0.0/0"));
        // the prefix is what decides it, whatever address is written in front
        assertFalse(Ipv4AddressUtils.isUsableTerminalAddress("192.168.40.38/0"));
    }

    /* Values naming addresses no terminal can be reached at. */

    @Test
    void refusesTheUnspecifiedAddress() {
        assertFalse(Ipv4AddressUtils.isUsableTerminalAddress("0.0.0.0"));
        assertFalse(Ipv4AddressUtils.isUsableTerminalAddress("0.0.0.0/8"));
        assertFalse(Ipv4AddressUtils.isUsableTerminalAddress("0.1.2.3"));
    }

    @Test
    void refusesBroadcastMulticastAndReserved() {
        assertFalse(Ipv4AddressUtils.isUsableTerminalAddress("255.255.255.255"));
        assertFalse(Ipv4AddressUtils.isUsableTerminalAddress("240.0.0.0/4"));
        assertFalse(Ipv4AddressUtils.isUsableTerminalAddress("224.0.0.0/4"));
        assertFalse(Ipv4AddressUtils.isUsableTerminalAddress("239.1.2.3"));
    }

    @Test
    void refusesARangeBroadEnoughToSwallowOneOfThose() {
        // 0.0.0.0 - 127.255.255.255, which takes in the unspecified block
        assertFalse(Ipv4AddressUtils.isUsableTerminalAddress("0.0.0.0/1"));
        // 128.0.0.0 - 255.255.255.255, which takes in multicast and the reserved block
        assertFalse(Ipv4AddressUtils.isUsableTerminalAddress("128.0.0.0/1"));
    }

    @Test
    void acceptsTheAddressJustBelowMulticast() {
        assertTrue(Ipv4AddressUtils.isUsableTerminalAddress("223.255.255.255"));
    }

    /* One terminal is one address: a range is not registered, only read back. */

    @Test
    void takesOneAddressAndNothingElseAsSingle() {
        assertTrue(Ipv4AddressUtils.isSingleAddress("192.168.40.38"));
        assertTrue(Ipv4AddressUtils.isSingleAddress("127.0.0.1"));
    }

    @Test
    void refusesEveryRangeAsSingleEvenOneHoldingOneAddress() {
        assertFalse(Ipv4AddressUtils.isSingleAddress("192.168.40.0/24"));
        assertFalse(Ipv4AddressUtils.isSingleAddress("192.168.40.38/32"));
        // still a range as far as this is concerned, though isValidAddressOrCidr takes it
        assertTrue(Ipv4AddressUtils.isValidAddressOrCidr("192.168.40.38/32"));
    }

    @Test
    void refusesWhatIsNotAnAddressAsSingle() {
        assertFalse(Ipv4AddressUtils.isSingleAddress("192.168.40.256"));
        assertFalse(Ipv4AddressUtils.isSingleAddress("Require ip 192.168.40.10"));
        assertFalse(Ipv4AddressUtils.isSingleAddress(""));
        assertFalse(Ipv4AddressUtils.isSingleAddress(null));
    }

    /* Malformed values, refused as they were before. */

    @Test
    void refusesWhatIsNotAnAddressOrRange() {
        assertFalse(Ipv4AddressUtils.isValidAddressOrCidr("192.168.40.256"));
        assertFalse(Ipv4AddressUtils.isValidAddressOrCidr("192.168.40.0/33"));
        assertFalse(Ipv4AddressUtils.isValidAddressOrCidr("192.168.40.0/"));
        assertFalse(Ipv4AddressUtils.isValidAddressOrCidr("192.168.40.0//24"));
        assertFalse(Ipv4AddressUtils.isValidAddressOrCidr("/24"));
        assertFalse(Ipv4AddressUtils.isValidAddressOrCidr("Require ip 192.168.40.10"));
        assertFalse(Ipv4AddressUtils.isValidAddressOrCidr(""));
        assertFalse(Ipv4AddressUtils.isValidAddressOrCidr(null));
    }

    @Test
    void refusesAPrefixWrittenTwoWays() {
        // only one spelling can be written back to the configuration
        assertFalse(Ipv4AddressUtils.isValidAddressOrCidr("192.168.40.0/024"));
    }

    @Test
    void refusesSomethingCarryingMoreThanOneLine() {
        assertFalse(Ipv4AddressUtils.isValidAddressOrCidr("192.168.40.1\n192.168.40.2"));
        assertFalse(Ipv4AddressUtils.isValidAddressOrCidr("192.168.40.1\r"));
    }

    @Test
    void malformedValuesAreNotUsableEither() {
        assertFalse(Ipv4AddressUtils.isUsableTerminalAddress("192.168.40.0/33"));
        assertFalse(Ipv4AddressUtils.isUsableTerminalAddress(null));
    }
}
