package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.ovirt.engine.core.bll.AuditStorageUsage.Target;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.dao.AuditStorageDao;
import org.ovirt.engine.core.dao.AuditStorageDao.EventTableUsage;

/**
 * At the critical DB filesystem level the oldest audit records are overwritten at once - the hour
 * of the capacity purge does not apply - and an archive on that same disk is not written.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class AuditLogDiskCriticalPurgeTest {

    private static final long MIB = 1024L * 1024L;
    private static final long GIB = 1024L * MIB;
    private static final String PGDATA = "/var/lib/pgsql/data";

    @Mock
    private AuditStorageDao auditStorageDao;

    @Mock
    private AuditLogDirector auditLogDirector;

    @Spy
    @InjectMocks
    private AuditLogPurger purger;

    @BeforeEach
    void records() {
        when(auditStorageDao.getEventTableUsage()).thenReturn(Collections.singletonList(
                new EventTableUsage("audit_log", 2 * GIB, GIB, 1024 * 1024)));
        when(auditStorageDao.getAuditLogTimeAfterOldest(anyLong()))
                .thenReturn(new Date(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(60)));
        when(auditStorageDao.countAuditLogOlderThan(any(Date.class))).thenReturn(100L);
        doReturn(new AuditLogPurger.Result(true, 100, "", null, null,
                "보관 위치가 DB 데이터와 같은 파일시스템이어서 보관하지 않음"))
                .when(purger).runHelper(anyString(), any(Date.class), any());
    }

    private static AuditStorageUsage eventTables(long liveBytes) {
        return AuditStorageUsage.informational(Target.EVENT_TABLES, "audit_log, event_*", liveBytes, "");
    }

    private static AuditStorageUsage database(long usedPercent) {
        return AuditStorageUsage.leveled(Target.DB_FILESYSTEM, PGDATA, usedPercent * GIB, 100 * GIB, "253:3",
                AuditStorageThresholds.DEFAULT, "");
    }

    @Test
    void overwritesAtOnceOnReachingTheCriticalLevelAndSkipsAnArchiveOnTheSameDisk() {
        purger.purgeForDiskCritical(eventTables(GIB), database(96));

        // 5% of 1 GiB made free at once, with the data directory handed over for the archive check.
        verify(purger, times(1)).runHelper(anyString(), any(Date.class), eq(PGDATA));
        verify(auditLogDirector).log(any(AuditLogable.class), eq(AuditLogType.AUDIT_LOG_RECORDS_PURGED_WITHOUT_ARCHIVE));
        assertTrue(purger.isInDiskCriticalProtection());
    }

    @Test
    void afterThatRemovesOnlyWhatTheTablesGrewAndNotMoreOftenThanTheInterval() {
        purger.purgeForDiskCritical(eventTables(GIB), database(96));
        // Within the interval nothing more is removed, however much the tables grew.
        purger.purgeForDiskCritical(eventTables(GIB + 100 * MIB), database(97));
        verify(purger, times(1)).runHelper(anyString(), any(Date.class), any());

        purger.leaveDiskCritical();
        assertFalse(purger.isInDiskCriticalProtection());
        purger.purgeForDiskCritical(eventTables(GIB), database(96));
        verify(purger, times(2)).runHelper(anyString(), any(Date.class), any());
    }

    @Test
    void everyRecordWithinTheMinimumRetentionIsKeptAndThatIsSaidOnce() {
        when(auditStorageDao.countAuditLogOlderThan(any(Date.class))).thenReturn(0L);
        purger.purgeForDiskCritical(eventTables(GIB), database(96));
        verify(purger, never()).runHelper(anyString(), any(Date.class), any());
        verify(auditLogDirector, times(1)).log(any(AuditLogable.class),
                eq(AuditLogType.AUDIT_LOG_CRITICAL_PURGE_BLOCKED));
    }

    @Test
    void theRoomMadeIsFivePercentWithinItsBounds() {
        assertEquals(GIB - GIB / 100 * 5, AuditLogPurger.criticalCeiling(GIB));
        assertEquals(100 * MIB - 16 * MIB, AuditLogPurger.criticalCeiling(100 * MIB));
        assertEquals(100 * GIB - 256 * MIB, AuditLogPurger.criticalCeiling(100 * GIB));
        assertEquals(0, AuditLogPurger.criticalCeiling(MIB));
    }

    @Test
    void protectionStartsAtTheCriticalLevelAndEndsBelowTheHighLevel() {
        assertTrue(AuditLogCapacityMonitor.keepsDiskCriticalProtection(database(95), false));
        assertTrue(AuditLogCapacityMonitor.keepsDiskCriticalProtection(database(100), false));
        assertFalse(AuditLogCapacityMonitor.keepsDiskCriticalProtection(database(92), false));
        // Once begun, held while the file system is at the high level - after the reserve is released.
        assertTrue(AuditLogCapacityMonitor.keepsDiskCriticalProtection(database(92), true));
        assertFalse(AuditLogCapacityMonitor.keepsDiskCriticalProtection(database(89), true));
        AuditStorageUsage unmeasured = AuditStorageUsage.unknown(Target.DB_FILESYSTEM, "", "x");
        assertTrue(AuditLogCapacityMonitor.keepsDiskCriticalProtection(unmeasured, true));
        assertFalse(AuditLogCapacityMonitor.keepsDiskCriticalProtection(unmeasured, false));
    }

    @Test
    void helperIsToldWhichFileSystemNotToArchiveOn() {
        Date cutoff = new Date(0);
        assertEquals(Arrays.asList("/usr/bin/sudo", "-n", AuditLogPurger.BACKUP_HELPER, "purge", "/archive",
                "1970-01-01T00:00:00Z", "--skip-archive-on-filesystem-of", PGDATA),
                AuditLogPurger.helperCommand("/archive", cutoff, PGDATA));
        assertEquals(6, AuditLogPurger.helperCommand("/archive", cutoff, null).size());
        assertEquals("보관 안 함", AuditLogPurger.parseHelperOutput(0,
                "SUCCESS\nDELETED: 3\nARCHIVE: \nARCHIVE_SKIPPED: 보관 안 함\n").getArchiveSkipped());
    }
}
