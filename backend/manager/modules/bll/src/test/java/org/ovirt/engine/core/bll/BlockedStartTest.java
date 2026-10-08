package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.ZoneId;

import org.junit.jupiter.api.Test;

/**
 * A start the verification gate refused leaves no engine to report it, so the record of it is
 * the only account there is, and the event it becomes at the next start is read in its place.
 */
class BlockedStartTest {

    private static final Instant REFUSED_AT = Instant.parse("2026-09-16T21:51:40Z");
    private static final ZoneId SEOUL = ZoneId.of("Asia/Seoul");

    private static SecurityAuditRunner.BlockedStart refusedFor(String reason,
            SecurityAuditRunner.Summary summary) {
        return new SecurityAuditRunner.BlockedStart(REFUSED_AT, reason, "", summary);
    }

    @Test
    void saysTheChecksFailedAndWhichTallyTheyFailedOn() {
        String message = refusedFor(SecurityAuditRunner.BlockedStart.CHECKS_FAILED,
                new SecurityAuditRunner.Summary(35, 2, 1)).describe(SEOUL);

        assertEquals("자체시험 실패 : 보안 점검에서 실패 항목이 확인됨 - 엔진 기동을 차단함 "
                + "(엔진 기동 전, 2026-09-17 06:51:40, 성공 35·경고 2·실패 1)", message);
    }

    @Test
    void saysWhenTheStartWasRefusedBeforeSayingWhy() {
        // Several of the reasons end in a clause of their own, and a time hung off the end of
        // one of those is read as part of it rather than as the time of the refusal.
        assertEquals("자체시험 실패 : 다른 보안 점검이 실행 중이어서 기동 점검을 할 수 없음 - 엔진 기동을 차단함 "
                + "(엔진 기동 전, 2026-09-17 06:51:40)",
                refusedFor(SecurityAuditRunner.BlockedStart.BUSY, null).describe(SEOUL));
    }

    @Test
    void doesNotCallAVerificationItCouldNotStartAFailedOne() {
        // 75 means nothing was checked, because another verification held the lock. Saying the
        // host failed its security checks would send an administrator after a fault that is
        // not there.
        String message = refusedFor(SecurityAuditRunner.BlockedStart.BUSY, null).describe();

        assertTrue(message.contains("다른 보안 점검이 실행 중"), message);
        assertTrue(!message.contains("실패 항목이 확인됨"), message);
    }

    @Test
    void namesTheScriptItCouldNotRun() {
        String message = refusedFor(SecurityAuditRunner.BlockedStart.RUNNER_MISSING, null).describe();

        assertTrue(message.contains(SecurityAuditRunner.RUNNER), message);
    }

    @Test
    void saysSomethingUsefulAboutAReasonItDoesNotKnow() {
        assertEquals("자체시험 실패 : 보안 점검 결과: the disk filled up - 엔진 기동을 차단함 "
                + "(엔진 기동 전, 2026-09-17 06:51:40)",
                new SecurityAuditRunner.BlockedStart(REFUSED_AT, "SOMETHING_NEW", "the disk filled up", null)
                        .describe(SEOUL));
        assertEquals("자체시험 실패 : 보안 점검 결과 - 엔진 기동을 차단함 (엔진 기동 전)",
                new SecurityAuditRunner.BlockedStart(null, null, null, null).describe(SEOUL));
    }

    @Test
    void leavesOutATallyForAnAuditThatNeverRan() {
        assertTrue(!refusedFor(SecurityAuditRunner.BlockedStart.ERROR, null).describe().contains("성공 "));
    }
}
