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
    void aRunFromThePortalIsNamedAsSuch() {
        String json = ScheduledVerificationFailureResponse.requestJson(
                ScheduledVerificationFailureResponse.REASON_MANUAL, "security",
                Instant.parse("2026-10-04T09:00:00Z"),
                Instant.parse("2026-10-04T09:05:00Z"),
                Instant.ofEpochSecond(1791104700L));
        assertTrue(json.contains("\"reason\": \"MANUAL_VERIFICATION_FAILED\""), json);
        assertEquals("The security verification run from the administration portal by admin",
                ScheduledVerificationFailureResponse.describeRun("security", true, "admin"));
        assertEquals("The scheduled integrity verification",
                ScheduledVerificationFailureResponse.describeRun("integrity", false, "admin"));
        String notice = ScheduledVerificationFailureResponse.haltNotice(300,
                " at 2026-10-07 09:24:45+0900", Path.of("/var/lib/ovirt-engine/security/halt-request.json"));
        assertTrue(notice.startsWith("엔진이 300초 후(2026-10-07 09:24:45+0900) 정지됩니다."), notice);
    }

    @Test
    void aFailedIntegrityVerificationAtStartIsNamedAsSuch() {
        String json = ScheduledVerificationFailureResponse.requestJson(
                ScheduledVerificationFailureResponse.REASON_START, "integrity",
                Instant.parse("2026-10-04T09:00:00Z"),
                Instant.parse("2026-10-04T09:05:00Z"),
                Instant.ofEpochSecond(1791104700L));
        assertTrue(json.contains("\"reason\": \"START_VERIFICATION_FAILED\""), json);
        assertEquals("The integrity verification run when the engine started",
                ScheduledVerificationFailureResponse.describeStartRun("integrity"));
    }

    @Test
    void everyFailedIntegrityVerificationIsRespondedToWhoeverRanIt() {
        for (String source : new String[] { "engine-start", "timer", "webadmin" }) {
            assertTrue(ScheduledVerificationFailureResponse.respondsTo("integrity", source), source);
        }
        assertTrue(ScheduledVerificationFailureResponse.respondsTo("security", "timer"));
        assertTrue(ScheduledVerificationFailureResponse.respondsTo("security", "webadmin"));
        // The start's own security audit is its gate: a start it fails does not happen.
        assertFalse(ScheduledVerificationFailureResponse.respondsTo("security", "engine-start"));
        assertFalse(ScheduledVerificationFailureResponse.respondsTo("integrity", "unknown"));
    }

    @Test
    void theSelfTestRunAfterTheEngineStartedIsRespondedToAndNamedAsSuch() {
        // The gate only warns about a process not yet running; the run after the start fails it.
        assertTrue(ScheduledVerificationFailureResponse.respondsTo("security", "engine-post-start"));
        assertEquals("The security verification run after the engine started",
                ScheduledVerificationFailureResponse.describePostStartRun("security"));
        assertEquals("POST_START_VERIFICATION_FAILED", ScheduledVerificationFailureResponse.REASON_POST_START);
    }

    @Test
    void aCheckThatCouldNotRunSaysTheEngineIsNotStopped() {
        String message = ScheduledVerificationFailureResponse.unverifiableMessage(
                ScheduledVerificationFailureResponse.describeStartRun("integrity"), null, "exit code 40");
        assertTrue(message.startsWith("The integrity verification run when the engine started could not be carried out"));
        assertTrue(message.contains("(exit code 40)"));
        assertTrue(message.contains("The engine is not stopped"));
        assertTrue(ScheduledVerificationFailureResponse.UNVERIFIABLE_NOTICE.contains("엔진은 정지하지 않습니다"));
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
