package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;

import org.junit.jupiter.api.Test;

/**
 * A start the verification gate refused leaves no engine to report it, so the record of it is
 * the only account there is, and the event it becomes at the next start is read in its place.
 */
class BlockedStartTest {

    private static final Instant REFUSED_AT = Instant.parse("2026-09-16T21:51:40Z");

    private static SecurityAuditRunner.BlockedStart refusedFor(String reason,
            SecurityAuditRunner.Summary summary) {
        return new SecurityAuditRunner.BlockedStart(REFUSED_AT, reason, "", summary);
    }

    @Test
    void saysTheChecksFailedAndWhichTallyTheyFailedOn() {
        String message = refusedFor(SecurityAuditRunner.BlockedStart.CHECKS_FAILED,
                new SecurityAuditRunner.Summary(35, 2, 1)).describe();

        assertEquals("The engine was prevented from starting because the security verification "
                + "reported failed checks; passed=35, warnings=2, failed=1", message);
    }

    @Test
    void saysWhenTheStartWasRefusedBeforeSayingWhy() {
        // Several of the reasons end in a clause of their own, and a time hung off the end of
        // one of those is read as part of it rather than as the time of the refusal.
        assertEquals("The engine was prevented from starting at 2026-09-17T06:51:40+09:00 "
                + "because another security verification was still running, so the start could "
                + "not be verified",
                refusedFor(SecurityAuditRunner.BlockedStart.BUSY, null)
                        .describe(" at 2026-09-17T06:51:40+09:00"));
    }

    @Test
    void doesNotCallAVerificationItCouldNotStartAFailedOne() {
        // 75 means nothing was checked, because another verification held the lock. Saying the
        // host failed its security checks would send an administrator after a fault that is
        // not there.
        String message = refusedFor(SecurityAuditRunner.BlockedStart.BUSY, null).describe();

        assertTrue(message.contains("another security verification was still running"), message);
        assertTrue(!message.contains("failed checks"), message);
    }

    @Test
    void namesTheScriptItCouldNotRun() {
        String message = refusedFor(SecurityAuditRunner.BlockedStart.RUNNER_MISSING, null).describe();

        assertTrue(message.contains(SecurityAuditRunner.RUNNER), message);
    }

    @Test
    void saysSomethingUsefulAboutAReasonItDoesNotKnow() {
        assertEquals("The engine was prevented from starting by the security verification: "
                + "the disk filled up",
                new SecurityAuditRunner.BlockedStart(REFUSED_AT, "SOMETHING_NEW", "the disk filled up", null)
                        .describe());
        assertEquals("The engine was prevented from starting by the security verification",
                new SecurityAuditRunner.BlockedStart(REFUSED_AT, null, null, null).describe());
    }

    @Test
    void leavesOutATallyForAnAuditThatNeverRan() {
        assertTrue(!refusedFor(SecurityAuditRunner.BlockedStart.ERROR, null).describe().contains("passed="));
    }
}
