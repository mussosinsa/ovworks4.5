package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.junit.jupiter.api.Test;

/**
 * What is written into the web server's {@code RequireAny} block when terminals are registered.
 *
 * <p>The block used to open with "Require all granted", which matched unconditionally and so let
 * every address through whatever these lines said. It is gone, which makes these lines the only
 * thing standing between a terminal and the engine - and makes what this class refuses to write
 * matter as much as what it writes.</p>
 */
public class TerminalIpConfigUtilsTest {

    @Test
    void shouldKeepSingleRequireIpOnItsOwnLineInsideRequireAnyBlock() throws Exception {
        String original = "<LocationMatch ^/ovirt-engine($|/)>\n"
                + "    <RequireAny>\n"
                + "         Require ip 10.10.10.10\n"
                + "    </RequireAny>\n"
                + "\n"
                + "    ProxyPassMatch ajp://127.0.0.1:8702 timeout=3600 retry=5\n"
                + "</LocationMatch>\n";

        String updated = TerminalIpConfigUtils.updateRequireIpInContent(original, "192.168.40.100");

        assertTrue(updated.contains("<RequireAny>\n         Require ip 127.0.0.1\n"
                + "         Require ip 192.168.40.100\n    </RequireAny>"));
    }

    @Test
    void shouldAcceptReportedTerminalIpAddress() throws Exception {
        String original = "<RequireAny>\n"
                + "    Require ip 127.0.0.1\n"
                + "</RequireAny>\n";

        String updated = TerminalIpConfigUtils.updateRequireIpInContent(original, "192.168.10.111");

        assertTrue(updated.contains("Require ip 192.168.10.111"));
    }

    @Test
    void shouldApplyMultiplePlainIpAddressesFromUi() throws Exception {
        String original = "<LocationMatch ^/ovirt-engine($|/)>\n"
                + "    <RequireAny>\n"
                + "         Require ip 10.10.10.10\n"
                + "    </RequireAny>\n"
                + "</LocationMatch>\n";

        String uiValue = "192.168.20.20\n192.168.20.21";

        String updated = TerminalIpConfigUtils.updateRequireIpInContent(original, uiValue);

        assertTrue(updated.contains("Require ip 192.168.20.20\n"
                + "         Require ip 192.168.20.21"));
    }

    @Test
    void shouldReturnAllIpAddressesForUiDisplay() {
        String original = "<LocationMatch ^/ovirt-engine($|/)>\n"
                + "    <RequireAny>\n"
                + "         Require ip 192.168.20.20\n"
                + "         Require ip 192.168.20.21\n"
                + "    </RequireAny>\n"
                + "</LocationMatch>\n";

        String readValue = TerminalIpConfigUtils.readRequireIpFromContent(original);
        assertEquals("192.168.20.20\n192.168.20.21", readValue);
    }

    /* One terminal is one address. */

    @Test
    void shouldRejectACidrRange() {
        String original = "<RequireAny>\n"
                + "    Require ip 10.10.10.10\n"
                + "</RequireAny>\n";

        // A range admits every machine in it, approved or not, which is not what registering a
        // terminal says.
        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, "192.168.20.0/24"));
        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, "10.10.3.0/24"));
        // even a range holding exactly one address: only one spelling goes into the configuration
        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, "192.168.20.110/32"));
    }

    @Test
    void shouldRejectACidrRangeMixedInWithAddresses() {
        String original = "<RequireAny>\n"
                + "    Require ip 10.10.10.10\n"
                + "</RequireAny>\n";

        assertThrows(IOException.class, () -> TerminalIpConfigUtils.updateRequireIpInContent(
                original,
                "192.168.20.110\n192.168.20.0/24"));
    }

    @Test
    void shouldReadBackRangesLeftByOlderConfigurations() {
        // Apache still honours them, and an administrator has to see one to be able to remove it
        String original = "<RequireAny>\n"
                + "    Require ip 127.0.0.1\n"
                + "    Require ip 192.168.40.0/24\n"
                + "</RequireAny>\n";

        assertEquals("127.0.0.1\n192.168.40.0/24",
                TerminalIpConfigUtils.readRequireIpFromContent(original));
    }

    @Test
    void shouldRejectInvalidCidrPrefix() {
        String original = "<RequireAny>\n"
                + "    Require ip 10.10.10.10\n"
                + "</RequireAny>\n";

        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, "192.168.40.0/33"));
    }

    @Test
    void shouldRejectApacheDirectivesFromUi() {
        String original = "<RequireAny>\n"
                + "    Require ip 10.10.10.10\n"
                + "</RequireAny>\n";

        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, "Require ip 192.168.40.10"));
    }

    @Test
    void shouldRejectAnAddressThatWouldLetEveryTerminalThrough() {
        String original = "<RequireAny>\n"
                + "    Require ip 10.10.10.10\n"
                + "</RequireAny>\n";

        // Written into the web server these read as a restriction while restricting nothing.
        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, "0.0.0.0"));
        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, "0.0.0.0/0"));
    }

    @Test
    void shouldRejectAnAddressNoTerminalCanHave() {
        String original = "<RequireAny>\n"
                + "    Require ip 10.10.10.10\n"
                + "</RequireAny>\n";

        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, "255.255.255.255"));
        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, "239.1.2.3"));
    }

    @Test
    void shouldRejectTheWholeListWhenOneEntryIsRefused() {
        String original = "<RequireAny>\n"
                + "    Require ip 10.10.10.10\n"
                + "</RequireAny>\n";

        // the configuration is written in one go, so a list is taken or refused in one go
        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, "192.168.40.10\n0.0.0.0"));
    }

    @Test
    void shouldStillAcceptOrdinaryTerminalAddresses() throws Exception {
        String original = "<RequireAny>\n"
                + "    Require ip 10.10.10.10\n"
                + "</RequireAny>\n";

        String updated = TerminalIpConfigUtils.updateRequireIpInContent(
                original,
                "192.168.40.38\n10.10.3.7\n127.0.0.1");

        assertTrue(updated.contains("Require ip 192.168.40.38"));
        assertTrue(updated.contains("Require ip 10.10.3.7"));
        assertTrue(updated.contains("Require ip 127.0.0.1"));
    }

    /* Nothing may leave the block empty, or without the address the engine reaches itself on. */

    @Test
    void shouldRefuseToEmptyTheList() {
        String original = "<RequireAny>\n"
                + "    Require ip 10.10.10.10\n"
                + "</RequireAny>\n";

        // With no unconditional allow left in the block, an empty list is a web server that
        // answers nobody - including whoever emptied it.
        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, "  "));
        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, null));
    }

    @Test
    void shouldKeepLoopbackOnTheListEvenWhenItIsNotSubmitted() throws Exception {
        String original = "<RequireAny>\n"
                + "    Require ip 10.10.10.10\n"
                + "</RequireAny>\n";

        String updated = TerminalIpConfigUtils.updateRequireIpInContent(original, "192.168.40.38");

        assertEquals("<RequireAny>\n"
                + "    Require ip 127.0.0.1\n"
                + "    Require ip 192.168.40.38\n"
                + "</RequireAny>\n", updated);
    }

    @Test
    void shouldNotWriteLoopbackTwiceWhenItIsSubmitted() throws Exception {
        String original = "<RequireAny>\n"
                + "    Require ip 10.10.10.10\n"
                + "</RequireAny>\n";

        String updated = TerminalIpConfigUtils.updateRequireIpInContent(
                original,
                "127.0.0.1\n192.168.40.38\n127.0.0.1");

        assertEquals("<RequireAny>\n"
                + "    Require ip 127.0.0.1\n"
                + "    Require ip 192.168.40.38\n"
                + "</RequireAny>\n", updated);
    }
}
