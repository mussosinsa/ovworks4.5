package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;

import org.junit.jupiter.api.Test;

/**
 * The lines the web server writes are the only account there is of an address it turned away, so
 * reading them wrongly loses the attempt entirely.
 */
class ClientAccessDeniedLogTest {

    private static final String LINE = "time=2026-09-17T07:31:07+0900 remote_ip=192.168.40.50 "
            + "request=\"GET /ovirt-engine/webadmin/ HTTP/1.1\" status=403 referer=\"-\" "
            + "user_agent=\"Mozilla/5.0 (X11; Linux x86_64)\"";

    @Test
    void readsWhoWasTurnedAwayAndFromWhat() {
        ClientAccessDeniedLog.Denial denial = ClientAccessDeniedLog.parse(LINE).orElseThrow();

        assertEquals("192.168.40.50", denial.getAddress());
        assertEquals("GET /ovirt-engine/webadmin/ HTTP/1.1", denial.getRequest());
        assertEquals("2026-09-17T07:31:07+0900", denial.getTime());
    }

    @Test
    void saysAllOfItInTheEventItRecords() {
        String message = ClientAccessDeniedLog.parse(LINE).orElseThrow().describe();

        assertTrue(message.contains("192.168.40.50"), message);
        assertTrue(message.contains("not registered"), message);
        assertTrue(message.contains("GET /ovirt-engine/webadmin/ HTTP/1.1"), message);
    }

    @Test
    void readsARequestThatCarriesSpacesAndQuotesAroundIt() {
        ClientAccessDeniedLog.Denial denial = ClientAccessDeniedLog.parse(
                "time=2026-09-17T07:31:07+0900 remote_ip=10.0.0.9 "
                        + "request=\"POST /ovirt-engine/api/vms HTTP/1.1\" status=403").orElseThrow();

        assertEquals("POST /ovirt-engine/api/vms HTTP/1.1", denial.getRequest());
    }

    @Test
    void leavesOutARequestTheWebServerDidNotRecord() {
        ClientAccessDeniedLog.Denial denial = ClientAccessDeniedLog.parse(
                "time=2026-09-17T07:31:07+0900 remote_ip=10.0.0.9 request=\"-\" status=403").orElseThrow();

        assertEquals("", denial.getRequest());
        assertTrue(denial.describe().contains("10.0.0.9"));
    }

    @Test
    void ignoresALineWithNoAddressInIt() {
        assertEquals(Optional.empty(), ClientAccessDeniedLog.parse(""));
        assertEquals(Optional.empty(), ClientAccessDeniedLog.parse(null));
        assertEquals(Optional.empty(), ClientAccessDeniedLog.parse("time=2026-09-17T07:31:07+0900 status=403"));
        assertEquals(Optional.empty(), ClientAccessDeniedLog.parse("remote_ip=- status=403"));
    }

    @Test
    void ignoresHalfALineCaughtWhileItWasBeingWritten() {
        assertEquals(Optional.empty(), ClientAccessDeniedLog.parse("time=2026-09-17T07:31:07+09"));
    }
}
