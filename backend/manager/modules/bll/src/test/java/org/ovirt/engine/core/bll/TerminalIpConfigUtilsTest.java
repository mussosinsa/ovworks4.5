package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.junit.jupiter.api.Test;

public class TerminalIpConfigUtilsTest {

    @Test
    void shouldKeepSingleRequireIpOnItsOwnLineInsideRequireAnyBlock() throws Exception {
        String original = "<LocationMatch ^/ovirt-engine($|/)>\n"
                + "    <RequireAny>\n"
                + "         Require all granted\n"
                + "         Require ip 10.10.10.10\n"
                + "    </RequireAny>\n"
                + "\n"
                + "    ProxyPassMatch ajp://127.0.0.1:8702 timeout=3600 retry=5\n"
                + "</LocationMatch>\n";

        String updated = TerminalIpConfigUtils.updateRequireIpInContent(original, "192.168.40.100");

        assertTrue(updated.contains("<RequireAny>\n         Require all granted\n"
                + "         Require ip 192.168.40.100\n    </RequireAny>"));
    }

    @Test
    void shouldApplyMultiplePlainIpAddressesFromUi() throws Exception {
        String original = "<LocationMatch ^/ovirt-engine($|/)>\n"
                + "    <RequireAny>\n"
                + "         Require all granted\n"
                + "         Require ip 10.10.10.10\n"
                + "    </RequireAny>\n"
                + "</LocationMatch>\n";

        String uiValue = "192.168.20.20\n192.168.20.21";

        String updated = TerminalIpConfigUtils.updateRequireIpInContent(original, uiValue);
        assertTrue(updated.contains("Require ip 192.168.20.20"));
        assertTrue(updated.contains("<RequireAny>\n         Require all granted\n"
                + "         Require ip 192.168.20.20\n"
                + "         Require ip 192.168.20.21\n    </RequireAny>"));
    }

    @Test
    void shouldReturnOnlyIpAddressesForUiDisplay() {
        String original = "<LocationMatch ^/ovirt-engine($|/)>\n"
                + "    <RequireAny>\n"
                + "         Require all granted\n"
                + "         Require ip 192.168.20.20\n"
                + "         Require ip 192.168.20.21\n"
                + "    </RequireAny>\n"
                + "</LocationMatch>\n";

        String readValue = TerminalIpConfigUtils.readRequireIpFromContent(original);
        assertEquals("192.168.20.20\n192.168.20.21", readValue);
    }

    @Test
    void shouldRejectCidrRangeInput() {
        String original = "<LocationMatch ^/ovirt-engine($|/)>\n"
                + "    <RequireAny>\n"
                + "         Require ip 10.10.10.10\n"
                + "    </RequireAny>\n"
                + "</LocationMatch>\n";

        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, "192.168.40.0/24"));
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
    void shouldRejectEmptyIpList() {
        String original = "<RequireAny>\n"
                + "    Require ip 10.10.10.10\n"
                + "</RequireAny>\n";

        assertThrows(IOException.class, () -> TerminalIpConfigUtils.updateRequireIpInContent(original, "  "));
    }
}
