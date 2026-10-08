package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.bll.AuditStorageThresholds.Level;
import org.ovirt.engine.core.dao.AuditStorageDao.EventTableUsage;

public class AuditLogPurgerTest {

    private static final long MIB = 1024L * 1024L;
    private static final long DAY = TimeUnit.DAYS.toMillis(1);
    private static final Date NOW = new Date(1_800_000_000_000L);

    @Test
    void removesEnoughOfTheOldestRecordsToReachTheTarget() {
        AtomicLong asked = new AtomicLong(-1);
        Date oldEnough = new Date(NOW.getTime() - 60 * DAY);
        // 110 MiB live against a 100 MiB limit and an 80% target: 30 MiB to free, at 1 KiB a record.
        AuditLogPurger.Plan plan = AuditLogPurger.planCapacityPurge(110 * MIB, 100 * MIB, 80,
                100 * MIB, 100 * 1024, records -> {
                    asked.set(records);
                    return oldEnough;
                }, NOW, 30);

        assertEquals(30 * 1024, asked.get());
        assertEquals(oldEnough, plan.getCutoff());
        assertFalse(plan.isLimitedByRetention());
    }

    @Test
    void neverRemovesRecordsYoungerThanTheMinimumRetention() {
        Date tooRecent = new Date(NOW.getTime() - 5 * DAY);
        AuditLogPurger.Plan plan = AuditLogPurger.planCapacityPurge(200 * MIB, 100 * MIB, 80,
                200 * MIB, 1000, records -> tooRecent, NOW, 30);

        assertEquals(new Date(NOW.getTime() - 30 * DAY), plan.getCutoff());
        assertTrue(plan.isLimitedByRetention());
    }

    @Test
    void removingEverythingIsStillBoundByTheMinimumRetention() {
        // Fewer records than would have to go: the cutoff would be now, and is held back.
        AuditLogPurger.Plan plan = AuditLogPurger.planCapacityPurge(200 * MIB, 100 * MIB, 80,
                200 * MIB, 10, records -> null, NOW, 30);

        assertEquals(new Date(NOW.getTime() - 30 * DAY), plan.getCutoff());
        assertTrue(plan.isLimitedByRetention());
    }

    @Test
    void doesNothingUnderTheTarget() {
        assertNull(AuditLogPurger.planCapacityPurge(79 * MIB, 100 * MIB, 80, 79 * MIB, 1000,
                records -> NOW, NOW, 30));
        assertNull(AuditLogPurger.planCapacityPurge(500 * MIB, 0, 80, 500 * MIB, 1000,
                records -> NOW, NOW, 30));
    }

    @Test
    void thePurgeEventSaysTheAuditRecordsWereActedOn() {
        assertEquals("[주의] 감사로그 용량 초과로 대응 작업을 진행했습니다.",
                AuditLogPurger.notice(AuditLogPurger.Reason.CAPACITY));
        assertEquals("[주의] 감사로그 용량 초과로 대응 작업을 진행했습니다.",
                AuditLogPurger.notice(AuditLogPurger.Reason.DISK_CRITICAL));
        assertEquals("[주의] 감사로그 보존기간 경과로 정리 작업을 진행했습니다.",
                AuditLogPurger.notice(AuditLogPurger.Reason.RETENTION));
    }

    @Test
    void readsWhatTheHelperRemovedAndWhereItWasArchived() {
        AuditLogPurger.Result result = AuditLogPurger.parseHelperOutput(0,
                "SUCCESS\nDELETED: 1234\nARCHIVE: /var/lib/ovirt-engine-backup/audit-log-purged/p.csv.gz\n");
        assertTrue(result.isSucceeded());
        assertEquals(1234, result.getDeleted());
        assertEquals("/var/lib/ovirt-engine-backup/audit-log-purged/p.csv.gz", result.getArchive());
        assertNull(result.getVacuumFailure());

        AuditLogPurger.Result vacuum = AuditLogPurger.parseHelperOutput(0,
                "SUCCESS\nDELETED: 1\nARCHIVE: /a.csv.gz\nVACUUM_FAILED: lock timeout\n");
        assertEquals("lock timeout", vacuum.getVacuumFailure());
    }

    @Test
    void aHelperFailureRemovesNothingAndSaysWhy() {
        AuditLogPurger.Result result = AuditLogPurger.parseHelperOutput(1, "FAIL: 이벤트 DB 작업 실패\n");
        assertFalse(result.isSucceeded());
        assertEquals(0, result.getDeleted());
        assertTrue(result.getError().contains("이벤트 DB 작업 실패"));
        assertFalse(AuditLogPurger.parseHelperOutput(1, "").isSucceeded());
    }

    @Test
    void liveSizeFallsWithTheRowsWhileThePhysicalSizeStays() {
        // 100 MiB table, 25 MiB of it heap; 10 000 rows of 1 000 bytes left after a purge.
        EventTableUsage usage = EventTableUsage.estimate("audit_log", 100 * MIB, 25 * MIB, 10_000, 1_000);
        long expected = Math.round(10_000.0 * (1_000 + 28) * 4);
        assertEquals(expected, usage.getLiveBytes());
        assertEquals(100 * MIB, usage.getTotalBytes());
    }

    @Test
    void anUnanalysedTableCountsWithItsPhysicalSize() {
        EventTableUsage usage = EventTableUsage.estimate("audit_log", 100 * MIB, 25 * MIB, 10_000, 0);
        assertEquals(100 * MIB, usage.getLiveBytes());
    }

    @Test
    void eventTablesAreLeveledAgainstTheirLimitOnlyWhenOneIsSet() {
        EventTableUsage auditLog = new EventTableUsage("audit_log", 150 * MIB, 95 * MIB, 1000);
        EventTableUsage eventMap = new EventTableUsage("event_map", MIB, 5 * MIB, 10);

        AuditStorageUsage limited = AuditLogCapacityMonitor.eventTablesUsage(Arrays.asList(auditLog, eventMap),
                100 * MIB, AuditStorageThresholds.DEFAULT);
        assertEquals(100 * MIB, limited.getUsedBytes());
        assertEquals(Level.FULL, limited.getLevel());
        assertTrue(limited.getDetail().contains("물리 크기"));

        AuditStorageUsage unlimited = AuditLogCapacityMonitor.eventTablesUsage(Arrays.asList(auditLog, eventMap),
                0, AuditStorageThresholds.DEFAULT);
        assertEquals(Level.NORMAL, unlimited.getLevel());
        assertTrue(unlimited.getUsedPercent() < 0);
    }
}
