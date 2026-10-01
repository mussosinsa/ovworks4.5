package org.ovirt.engine.core.uutils.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck.Refusal;

public class ClientSerialCheckTest {

    private static final String SERIAL = "TERMINAL-0001";

    @Test
    void letsTheRegisteredSerialIn() {
        assertNull(ClientSerialCheck.check(SERIAL, SERIAL));
    }

    @Test
    void tellsAMissingHeaderFromAWrongOne() {
        assertEquals(Refusal.MISSING, ClientSerialCheck.check(null, SERIAL));
        assertEquals(Refusal.MISSING, ClientSerialCheck.check("", SERIAL));
        assertEquals(Refusal.INVALID, ClientSerialCheck.check("TERMINAL-0002", SERIAL));
        assertEquals(Refusal.INVALID, ClientSerialCheck.check(SERIAL + " ", SERIAL));
    }

    @Test
    void letsNothingInWhenTheRegisteredSerialCannotBeRead() {
        // An empty registered serial must not turn into "anything matches".
        assertEquals(Refusal.UNVERIFIABLE, ClientSerialCheck.check(SERIAL, null));
        assertEquals(Refusal.UNVERIFIABLE, ClientSerialCheck.check(SERIAL, ""));
        assertEquals(Refusal.MISSING, ClientSerialCheck.check(null, null));
    }

    @Test
    void theDescriptionSaysWhereAndWhyButNeverWhatWasPresented() {
        String description = ClientSerialCheck.describe("/ovirt-engine/sso/oauth/token", Refusal.INVALID);

        assertTrue(description.startsWith("/ovirt-engine/sso/oauth/token presented "), description);
        assertTrue(description.contains("does not match"), description);
        assertFalse(description.contains(SERIAL), description);
    }

    @Test
    void oneSourceIsRecordedOnceAMinutePerPlaceAndReason() {
        AtomicLong now = new AtomicLong(1_000_000L);
        ClientSerialCheck check = new ClientSerialCheck(now::get);

        assertTrue(check.isDue("10.0.0.5", "/ovirt-engine/", Refusal.MISSING));
        assertFalse(check.isDue("10.0.0.5", "/ovirt-engine/", Refusal.MISSING));
        // Another source, place or reason is news of its own.
        assertTrue(check.isDue("10.0.0.6", "/ovirt-engine/", Refusal.MISSING));
        assertTrue(check.isDue("10.0.0.5", "/ovirt-engine/sso/oauth/token", Refusal.MISSING));
        assertTrue(check.isDue("10.0.0.5", "/ovirt-engine/", Refusal.INVALID));

        now.addAndGet(ClientSerialCheck.REPORT_INTERVAL_MILLIS - 1);
        assertFalse(check.isDue("10.0.0.5", "/ovirt-engine/", Refusal.MISSING));
        now.addAndGet(1);
        assertTrue(check.isDue("10.0.0.5", "/ovirt-engine/", Refusal.MISSING));
    }

    @Test
    void manySourcesDoNotGrowTheMemoryWithoutBound() {
        ClientSerialCheck check = new ClientSerialCheck(() -> 0L);
        for (int i = 0; i < ClientSerialCheck.MAX_REMEMBERED + 5; i++) {
            assertTrue(check.isDue("10.0." + i, "/", Refusal.MISSING));
        }
    }
}
