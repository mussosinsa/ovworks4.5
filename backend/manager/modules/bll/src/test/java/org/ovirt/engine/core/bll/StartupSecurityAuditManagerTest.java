package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.time.ZoneId;

import org.junit.jupiter.api.Test;

/**
 * The time in the message and the time beside it in the event list are read together, so they have
 * to be the same reading of the same moment.
 */
class StartupSecurityAuditManagerTest {

    private static final Instant AUDIT_RAN_AT = Instant.parse("2026-09-16T21:51:40Z");

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
    void saysNothingAboutATimeTheAuditDidNotRecord() {
        assertEquals("", StartupSecurityAuditManager.at(null, ZoneId.of("Asia/Seoul")));
    }
}
