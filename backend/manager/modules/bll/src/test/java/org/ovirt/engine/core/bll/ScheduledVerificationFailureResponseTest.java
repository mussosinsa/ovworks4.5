package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ScheduledVerificationFailureResponseTest {

    @Test
    void stopsUnlessToldOnlyToNotify() {
        assertEquals("STOP", ScheduledVerificationFailureResponse.action(null));
        assertEquals("STOP", ScheduledVerificationFailureResponse.action("STOP"));
        assertEquals("NOTIFY", ScheduledVerificationFailureResponse.action("NOTIFY"));
        assertEquals("NOTIFY", ScheduledVerificationFailureResponse.action(" notify "));
        // A misspelt setting must not be able to turn the stop off quietly.
        assertEquals("STOP", ScheduledVerificationFailureResponse.action("NOTFY"));
        assertEquals("STOP", ScheduledVerificationFailureResponse.action(""));
    }

    @Test
    void keepsTheDelayWithinAnHour() {
        assertEquals(300, ScheduledVerificationFailureResponse.delaySeconds(null));
        assertEquals(0, ScheduledVerificationFailureResponse.delaySeconds(-5));
        assertEquals(120, ScheduledVerificationFailureResponse.delaySeconds(120));
        assertEquals(3600, ScheduledVerificationFailureResponse.delaySeconds(86400));
    }

    @Test
    void doesNotStopAnEngineThatStartedAfterTheFailedRun() {
        Instant started = Instant.parse("2026-10-04T00:00:00Z");
        assertFalse(ScheduledVerificationFailureResponse.ranWhileRunning(
                Instant.parse("2026-10-03T17:30:00Z"), started));
        assertTrue(ScheduledVerificationFailureResponse.ranWhileRunning(
                Instant.parse("2026-10-04T09:00:00Z"), started));
        assertTrue(ScheduledVerificationFailureResponse.ranWhileRunning(null, started));
    }

    @Test
    void theRequestSaysWhenToStop() {
        String json = ScheduledVerificationFailureResponse.requestJson("integrity",
                Instant.parse("2026-10-04T09:00:00Z"),
                Instant.parse("2026-10-04T09:05:00Z"),
                Instant.ofEpochSecond(1791104700L));
        assertTrue(json.contains("\"not_before\": 1791104700"), json);
        assertTrue(json.contains("\"check\": \"integrity\""), json);
        assertTrue(json.contains("\"reason\": \"SCHEDULED_VERIFICATION_FAILED\""), json);
    }

    @Test
    void aRequestNobodyCarriedOutIsNotTakenAsPending(@TempDir Path dir) throws IOException {
        Path request = Files.write(dir.resolve("halt-request.json"), new byte[0]);
        Instant now = Instant.parse("2026-10-04T12:00:00Z");
        Files.setLastModifiedTime(request, FileTime.from(now.minusSeconds(600)));
        assertFalse(ScheduledVerificationFailureResponse.isStale(request, now));
        Files.setLastModifiedTime(request, FileTime.from(now.minusSeconds(3600 + 901)));
        assertTrue(ScheduledVerificationFailureResponse.isStale(request, now));
        assertFalse(ScheduledVerificationFailureResponse.isStale(dir.resolve("missing"), now));
    }
}
