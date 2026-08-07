package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.junit.jupiter.api.Test;

public class TerminalIpConfigUtilsTest {

    @Test
    void shouldKeepSingleRequireIpOnItsOwnLineInsideRequireAllBlock() throws Exception {
        String original = "<LocationMatch ^/ovirt-engine($|/)>\n"
                + "    <RequireAll>\n"
                + "         Require ip 10.10.10.10\n"
                + "    </RequireAll>\n"
                + "\n"
                + "    ProxyPassMatch ajp://127.0.0.1:8702 timeout=3600 retry=5\n"
                + "</LocationMatch>\n";

        String updated = TerminalIpConfigUtils.updateRequireIpInContent(original, "192.168.40.100");

        assertTrue(updated.contains("<RequireAll>\n         Require ip 192.168.40.100\n    </RequireAll>"));
    }

    @Test
    void shouldAcceptRequireAllWrappedInputFromUi() throws Exception {
        String original = "<LocationMatch ^/ovirt-engine($|/)>\n"
                + "    <RequireAll>\n"
                + "         Require ip 10.10.10.10\n"
                + "    </RequireAll>\n"
                + "</LocationMatch>\n";

        String uiValue = "<RequireAll>\n"
                + "                Require ip 192.168.20.20\n"
                + "</RequireAll>";

        String updated = TerminalIpConfigUtils.updateRequireIpInContent(original, uiValue);
        assertTrue(updated.contains("Require ip 192.168.20.20"));
        assertTrue(updated.contains("<RequireAll>\n         Require ip 192.168.20.20\n    </RequireAll>"));
    }

    @Test
    void shouldReturnRequireAllWrappedValueForUiDisplay() {
        String original = "<LocationMatch ^/ovirt-engine($|/)>\n"
                + "    <RequireAll>\n"
                + "         Require ip 192.168.20.0/24\n"
                + "    </RequireAll>\n"
                + "</LocationMatch>\n";

        String readValue = TerminalIpConfigUtils.readRequireIpFromContent(original);
        assertEquals("<RequireAll>\n                Require ip 192.168.20.0/24\n</RequireAll>", readValue);
    }

    @Test
    void shouldRejectCidrRangeInput() {
        String original = "<LocationMatch ^/ovirt-engine($|/)>\n"
                + "    <RequireAll>\n"
                + "         Require ip 10.10.10.10\n"
                + "    </RequireAll>\n"
                + "</LocationMatch>\n";

        assertThrows(IOException.class, () ->
                TerminalIpConfigUtils.updateRequireIpInContent(original, "192.168.40.0/24"));
    }
}
