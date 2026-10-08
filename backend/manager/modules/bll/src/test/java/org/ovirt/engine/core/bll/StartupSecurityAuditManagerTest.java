package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The time in the message and the time beside it in the event list are read together, so they have
 * to be the same reading of the same moment.
 */
class StartupSecurityAuditManagerTest {

    private static final Instant AUDIT_RAN_AT = Instant.parse("2026-09-16T21:51:40Z");

    @Test
    void theSelfTestIsRunAgainFiveMinutesAfterTheStartAndJudgedInFull() {
        assertEquals(300, StartupSecurityAuditManager.POST_START_AUDIT_DELAY_SECONDS);
        assertEquals("engine-post-start", StartupSecurityAuditManager.ENGINE_POST_START);
        assertEquals("엔진 기동 후", VerificationFailureReport.sourceName("engine-post-start"));
    }

    @Test
    void writesTheTimeOfTheAuditInTheEnginesOwnTime() {
        assertEquals(" at 2026-09-17T06:51:40+09:00",
                StartupSecurityAuditManager.at(AUDIT_RAN_AT, ZoneId.of("Asia/Seoul")));
    }

    @Test
    void spellsOutTheOffsetSoTheTimeIsNotAmbiguous() {
        assertEquals(" at 2026-09-16T21:51:40Z",
                StartupSecurityAuditManager.at(AUDIT_RAN_AT, ZoneId.of("UTC")));
        assertEquals(" at 2026-09-16T17:51:40-04:00",
                StartupSecurityAuditManager.at(AUDIT_RAN_AT, ZoneId.of("America/New_York")));
    }

    @Test
    void readsTheRunsTheRunnerSkipped() {
        List<SecurityAuditRunner.SkippedRun> runs = SecurityAuditRunner.parseSkippedRuns(Arrays.asList(
                "2026-10-03T09:00:00Z\tall\ttimer",
                "2026-10-03T09:00:00Z\tall\ttimer; DROP",
                "not a line",
                "2026-10-03T21:00:00Z\tsecurity\tmanual"));
        assertEquals(2, runs.size());
        assertEquals(Instant.parse("2026-10-03T09:00:00Z"), runs.get(0).getTimestamp());
        assertEquals("all", runs.get(0).getMode());
        assertEquals("timer", runs.get(0).getSource());
        assertEquals("manual", runs.get(1).getSource());
    }

    @Test
    void saysASkippedRunCheckedNothing() {
        String message = StartupSecurityAuditManager.describeSkipped(
                SecurityAuditRunner.parseSkippedRuns(Arrays.asList("2026-10-03T09:00:00Z\tall\ttimer")).get(0),
                ZoneId.of("Asia/Seoul"));
        assertEquals("Security verification (timer, all) at 2026-10-03T18:00:00+09:00 did not run: "
                + "another verification was in progress, so nothing was checked", message);
        assertTrue(message.contains("did not run"));
    }

    @Test
    void saysNothingAboutATimeTheAuditDidNotRecord() {
        assertEquals("", StartupSecurityAuditManager.at(null, ZoneId.of("Asia/Seoul")));
    }
}
