package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.junit.jupiter.api.Test;

/**
 * AIDE walks the whole filesystem, so whether a start runs one decides whether every restart
 * costs minutes of disk - and whether a host is taken to be intact on yesterday's word.
 */
class IntegrityVerificationOnStartTest {

    private static final Instant NOW = Instant.parse("2026-09-17T06:00:00Z");

    private static boolean onStart(String configured, Instant lastRun) {
        return IntegrityVerificationAuditManager.shouldVerifyOnStart(configured, lastRun, NOW);
    }

    @Test
    void verifiesAHostThatHasNotBeenVerifiedSinceYesterday() {
        assertTrue(onStart(null, NOW.minus(13, ChronoUnit.HOURS)));
    }

    @Test
    void leavesAHostAloneThatWasVerifiedThisMorning() {
        // Restarts come in threes when somebody is working on a host, and a full AIDE run for
        // each of them is minutes of disk for an answer given minutes ago.
        assertFalse(onStart(null, NOW.minus(2, ChronoUnit.HOURS)));
    }

    @Test
    void verifiesAHostThatHasNeverBeenVerified() {
        // No result at all is the case this is most worth running for, whatever an age would
        // have said about it.
        assertTrue(onStart(null, null));
    }

    @Test
    void doesAsItIsTold() {
        assertFalse(onStart("false", null));
        assertFalse(onStart("FALSE", NOW.minus(30, ChronoUnit.DAYS)));
        assertTrue(onStart("always", NOW));
        assertTrue(onStart("ALWAYS", NOW.minus(1, ChronoUnit.SECONDS)));
    }

    @Test
    void treatsAnythingElseItIsToldAsNotHavingBeenTold() {
        // A misspelt setting must not quietly turn the verification off.
        assertTrue(onStart("yes", null));
        assertTrue(onStart("", NOW.minus(13, ChronoUnit.HOURS)));
        assertFalse(onStart("disabled", NOW.minus(1, ChronoUnit.HOURS)));
    }

    @Test
    void saysThatTheVerificationFollowedTheStartRatherThanNamingTheSource() {
        assertEquals(" after the engine started",
                IntegrityVerificationAuditManager.ranBy(
                        IntegrityVerificationAuditManager.ENGINE_START));
        assertEquals(" (timer)", IntegrityVerificationAuditManager.ranBy("timer"));
        assertEquals("", IntegrityVerificationAuditManager.ranBy(""));
    }
}
