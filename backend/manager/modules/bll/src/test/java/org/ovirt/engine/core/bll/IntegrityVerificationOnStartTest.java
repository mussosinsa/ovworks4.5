package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Paths;
import java.time.Instant;

import org.junit.jupiter.api.Test;

/**
 * What a start says about the integrity verification. Every start runs one (nothing turns it
 * off); until it has finished, the start says what the last one found.
 */
class IntegrityVerificationOnStartTest {

    private static final Instant NOW = Instant.parse("2026-09-17T06:00:00Z");

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
