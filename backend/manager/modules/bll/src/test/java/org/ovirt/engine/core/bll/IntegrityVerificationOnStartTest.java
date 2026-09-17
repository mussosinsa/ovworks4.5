package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Paths;
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
    void verifiesAtEveryStart() {
        // However recently the last one ran, and whoever ran it: what the host is now is the
        // question a start asks, and yesterday's answer is not it.
        assertTrue(onStart(null, NOW.minus(13, ChronoUnit.HOURS)));
        assertTrue(onStart(null, NOW.minus(2, ChronoUnit.HOURS)));
        assertTrue(onStart(null, NOW.minus(1, ChronoUnit.SECONDS)));
        assertTrue(onStart(null, NOW));
    }

    @Test
    void verifiesAHostThatHasNeverBeenVerified() {
        // No result at all is the case this is most worth running for.
        assertTrue(onStart(null, null));
        assertTrue(onStart("stale", null));
    }

    @Test
    void doesAsItIsTold() {
        assertFalse(onStart("false", null));
        assertFalse(onStart("FALSE", NOW.minus(30, ChronoUnit.DAYS)));
        assertTrue(onStart("always", NOW));
    }

    @Test
    void spacesOutTheRunsOnAHostToldToCareAboutTheCost() {
        // AIDE walks the whole filesystem, and restarts come in threes when somebody is working
        // on a host. "stale" buys that back, at the price of a start being told what was true
        // this morning.
        assertTrue(onStart("stale", NOW.minus(13, ChronoUnit.HOURS)));
        assertFalse(onStart("stale", NOW.minus(2, ChronoUnit.HOURS)));
        assertFalse(onStart("STALE", NOW.minus(1, ChronoUnit.SECONDS)));
    }

    @Test
    void treatsAnythingElseItIsToldAsNotHavingBeenTold() {
        // A misspelt setting must not quietly turn the verification off, so anything unknown
        // falls to the default, which runs it.
        assertTrue(onStart("yes", null));
        assertTrue(onStart("", NOW.minus(13, ChronoUnit.HOURS)));
        assertTrue(onStart("disabled", NOW.minus(1, ChronoUnit.HOURS)));
        assertTrue(onStart("stale-ish", NOW));
    }

    private static IntegrityVerification.Result last(String status, int exitCode, String source) {
        return new IntegrityVerification.Result(NOW, status, exitCode, source,
                Paths.get("/var/log/ovirt-engine/integrity-verification-x.log"));
    }

    @Test
    void saysAtEveryStartWhatTheLastVerificationFound() {
        // A start within the twelve hours runs no verification, and the event list showed
        // nothing at all then - a host with three altered files and a host verified clean
        // looked exactly alike at the moment of a start.
        assertEquals("At engine start, the last integrity verification (timer) at 06:00 had "
                + "found 3 file(s) no longer matching the integrity database; "
                + "see /var/log/ovirt-engine/integrity-verification-x.log",
                IntegrityVerificationAuditManager.asItStood(last("FAIL", 7, "timer"), " at 06:00", 3));

        assertEquals("At engine start, the last integrity verification (timer) at 06:00 had "
                + "found no file differing from the integrity database; "
                + "see /var/log/ovirt-engine/integrity-verification-x.log",
                IntegrityVerificationAuditManager.asItStood(last("PASS", 0, "timer"), " at 06:00", 0));
    }

    @Test
    void doesNotCallAVerificationThatCouldNotRunACleanOne() {
        String message = IntegrityVerificationAuditManager.asItStood(
                last("ERROR", 18, "timer"), " at 06:00", 0);

        assertTrue(message.contains("had not been able to carry out the check"), message);
        assertTrue(message.contains("18"), message);
        assertFalse(message.contains("no file differing"), message);
    }

    @Test
    void doesNotSayAnEarlierVerificationRanAfterThisStart() {
        // It is the verification this start inherited, whatever produced it. Saying "after the
        // engine started" of a run from yesterday's timer would date it to this start.
        String message = IntegrityVerificationAuditManager.asItStood(
                last("PASS", 0, "engine-start"), " at 06:00", 0);

        assertTrue(message.contains("(engine-start)"), message);
        assertFalse(message.contains("after the engine started"), message);
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
