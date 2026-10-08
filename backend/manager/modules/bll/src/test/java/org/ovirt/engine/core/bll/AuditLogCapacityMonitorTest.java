package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.ovirt.engine.core.bll.AuditStorageThresholds.Level;
import org.ovirt.engine.core.bll.AuditStorageUsage.Target;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.businessentities.AuditLogCapacityStatus;
import org.ovirt.engine.core.common.config.Config;
import org.ovirt.engine.core.common.config.ConfigCommon;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.utils.MockConfigDescriptor;
import org.ovirt.engine.core.utils.MockConfigExtension;

@ExtendWith({ MockConfigExtension.class, MockitoExtension.class })
@MockitoSettings(strictness = Strictness.LENIENT)
// Public, because MockConfigExtension calls mockConfiguration() reflectively from another package:
// on a package-private class that call is refused, the refusal is swallowed and no configuration is
// mocked at all.
public class AuditLogCapacityMonitorTest {

    /** A limit small enough that a file of a few bytes moves the reading across the thresholds. */
    private static final long LIMIT_MIB = 1;

    private static final long LIMIT_BYTES = LIMIT_MIB * 1024L * 1024L;

    private static final long GIB = 1024L * 1024L * 1024L;
    private static final AuditStorageThresholds THRESHOLDS = AuditStorageThresholds.DEFAULT;

    @TempDir
    Path temporaryDirectory;

    @Mock
    private AuditLogDirector auditLogDirector;

    @InjectMocks
    private AuditLogCapacityMonitor monitor;

    public static Stream<MockConfigDescriptor<?>> mockConfiguration() {
        return Stream.of(
                MockConfigDescriptor.of(ConfigValues.ENGINE_AUDIT_LOG_MAX_SIZE_MB, LIMIT_MIB),
                MockConfigDescriptor.of(ConfigValues.ENGINE_AUDIT_LOG_CAPACITY_CHECK_INTERVAL_SECONDS, 60L),
                MockConfigDescriptor.of(ConfigValues.ENGINE_AUDIT_LOG_DIR, ""),
                MockConfigDescriptor.of(ConfigValues.ENGINE_AUDIT_EVENT_TABLES_MAX_SIZE_MB, 10240L));
    }

    @Test
    public void saysThereIsNoForecastYetInsteadOfLeavingItEmpty() {
        // An empty value is written as <UNKNOWN> by the message resolver.
        long now = TimeUnit.HOURS.toMillis(100);
        assertEquals(", growth trend not available yet",
                AuditLogCapacityMonitor.forecastText(null, now, 10, 100));
        AuditLogCapacityMonitor.GrowthTracker tracker = new AuditLogCapacityMonitor.GrowthTracker();
        tracker.add(now - TimeUnit.MINUTES.toMillis(1), 10);
        assertEquals(", growth trend not available yet",
                AuditLogCapacityMonitor.forecastText(tracker, now, 10, 100));
    }

    @Test
    public void saysAStoreThatIsNotGrowingIsNotGrowing() {
        long now = TimeUnit.HOURS.toMillis(100);
        AuditLogCapacityMonitor.GrowthTracker tracker = new AuditLogCapacityMonitor.GrowthTracker();
        tracker.add(now - TimeUnit.HOURS.toMillis(1), 10);
        assertEquals(", not growing", AuditLogCapacityMonitor.forecastText(tracker, now, 10, 100));
    }

    @Test
    public void forecastsAGrowingStore() {
        long now = TimeUnit.HOURS.toMillis(100);
        AuditLogCapacityMonitor.GrowthTracker tracker = new AuditLogCapacityMonitor.GrowthTracker();
        tracker.add(now - TimeUnit.HOURS.toMillis(1), 10);
        assertTrue(AuditLogCapacityMonitor.forecastText(tracker, now, 20, 100)
                .startsWith(", growing "));
    }

    @Test
    void warnsWhenFivePercentOrLessRemains() {
        assertFalse(AuditLogCapacityMonitor.isWithinWarningRange(94, 100, 5));
        assertTrue(AuditLogCapacityMonitor.isWithinWarningRange(95, 100, 5));
        assertTrue(AuditLogCapacityMonitor.isWithinWarningRange(99, 100, 5));
    }

    @Test
    void exceededCapacityIsNotReportedAsWarning() {
        assertFalse(AuditLogCapacityMonitor.isWithinWarningRange(100, 100, 5));
        assertFalse(AuditLogCapacityMonitor.isWithinWarningRange(101, 100, 5));
    }

    @Test
    void namesTheStateTheReadingIsIn() {
        assertEquals(AuditLogCapacityStatus.State.NORMAL,
                AuditLogCapacityMonitor.capacityState(94, 100));
        assertEquals(AuditLogCapacityStatus.State.WARNING,
                AuditLogCapacityMonitor.capacityState(95, 100));
        assertEquals(AuditLogCapacityStatus.State.EXCEEDED,
                AuditLogCapacityMonitor.capacityState(100, 100));
        // Over the limit is still EXCEEDED, not a second, worse thing.
        assertEquals(AuditLogCapacityStatus.State.EXCEEDED,
                AuditLogCapacityMonitor.capacityState(150, 100));
    }

    @Test
    void barIsNotDrawnLongerThanTheBoxItIsDrawnIn() {
        AuditLogCapacityStatus status = new AuditLogCapacityStatus();
        status.setMaxBytes(100);

        status.setUsedBytes(30);
        assertEquals(30, status.getUsedPercent());
        // The space in use can pass the limit; a bar wider than the box it is drawn in reads as a
        // rendering fault rather than as the fact it is reporting.
        status.setUsedBytes(150);
        assertEquals(100, status.getUsedPercent());
        // And a limit of zero is monitoring switched off, not a division.
        status.setMaxBytes(0);
        assertEquals(0, status.getUsedPercent());
    }

    @Test
    void saysMonitoringIsOffRatherThanShowingAnEmptyStorage() {
        // configure() has not been called, which is the same state a screen sees on a host whose
        // limit or interval is set to zero. An administrator has to be told that, rather than left
        // to infer it from a panel showing nothing.
        AuditLogCapacityStatus status = monitor.getStatus();

        assertEquals(AuditLogCapacityStatus.State.DISABLED, status.getState());
        assertFalse(status.isMeasured());
        assertNull(status.getMeasuredAt());
    }

    @Test
    void readsTheLimitAndThePathTheConfigurationNames() {
        assertTrue(configure());

        AuditLogCapacityStatus status = monitor.getStatus();
        assertEquals(temporaryDirectory.toString(), status.getDirectory());
        assertEquals(LIMIT_BYTES, status.getMaxBytes());
        assertEquals(60, status.getCheckIntervalSeconds());
        assertEquals(AuditLogCapacityMonitor.WARNING_REMAINING_PERCENT,
                status.getWarningRemainingPercent());
    }

    @Test
    void measuresOnDemandWhenTheMonitorHasNotMeasuredYet() throws IOException {
        Files.write(temporaryDirectory.resolve("engine.log"), new byte[(int) (LIMIT_BYTES / 4)]);
        configure();

        AuditLogCapacityStatus status = monitor.getStatus();

        // A screen opened in the first minute after a start would otherwise show nothing at all.
        assertTrue(status.isMeasuredOnDemand());
        assertEquals(AuditLogCapacityStatus.State.NORMAL, status.getState());
        assertEquals(LIMIT_BYTES / 4, status.getUsedBytes());
        assertEquals(75, status.getRemainingPercent());
        assertNotNull(status.getMeasuredAt());
        // Kept, so a second screen opened a moment later does not walk the directory again.
        assertFalse(monitor.getStatus().isMeasuredOnDemand());
    }

    @Test
    void showsWhatTheScheduledPassMeasured() throws IOException {
        // 96% of the limit: inside it, and within the margin the engine warns at.
        Files.write(temporaryDirectory.resolve("engine.log"), new byte[(int) (LIMIT_BYTES / 100 * 96)]);
        configure();

        monitor.checkCapacity(temporaryDirectory, LIMIT_BYTES);
        AuditLogCapacityStatus status = monitor.getStatus();

        assertFalse(status.isMeasuredOnDemand());
        assertEquals(AuditLogCapacityStatus.State.WARNING, status.getState());
        assertEquals(4, status.getRemainingPercent());
    }

    @Test
    void reportsTheLimitBeingReachedAsReachedAndNotAsAWarning() throws IOException {
        Files.write(temporaryDirectory.resolve("engine.log"), new byte[(int) LIMIT_BYTES]);
        configure();

        monitor.checkCapacity(temporaryDirectory, LIMIT_BYTES);
        AuditLogCapacityStatus status = monitor.getStatus();

        assertEquals(AuditLogCapacityStatus.State.EXCEEDED, status.getState());
        assertEquals(0, status.getRemainingPercent());
        assertEquals(100, status.getUsedPercent());
    }

    @Test
    void aMeasurementThatCouldNotBeTakenIsNotReportedAsAnEmptyStorage() throws IOException {
        Files.write(temporaryDirectory.resolve("engine.log"), new byte[16]);
        configure();
        monitor.checkCapacity(temporaryDirectory, LIMIT_BYTES);
        assertTrue(monitor.getStatus().isMeasured());

        monitor.checkCapacity(temporaryDirectory.resolve("no-such-directory"), LIMIT_BYTES);

        // Leaving the last figure standing would show a size from before the directory became
        // unreadable, with nothing to say that it is no longer being measured.
        AuditLogCapacityStatus status = monitor.getStatus();
        assertEquals(AuditLogCapacityStatus.State.UNAVAILABLE, status.getState());
        assertFalse(status.isMeasured());
        assertTrue(status.getUnavailableReason().contains("IOException"),
                status.getUnavailableReason());
    }

    @Test
    void calculatesRegularFilesRecursivelyWithoutFollowingSymbolicLinks() throws IOException {
        Files.write(temporaryDirectory.resolve("engine.log"), new byte[11]);
        Path archive = Files.createDirectory(temporaryDirectory.resolve("archive"));
        Files.write(archive.resolve("engine.log.1"), new byte[17]);
        Files.createSymbolicLink(temporaryDirectory.resolve("archive-link"), archive);

        assertEquals(28, AuditLogCapacityMonitor.calculateDirectorySize(temporaryDirectory));
    }

    @Test
    void levelsFollowTheConfiguredThresholds() {
        assertEquals(Level.NORMAL, THRESHOLDS.levelOf(69.9));
        assertEquals(Level.NOTICE, THRESHOLDS.levelOf(70));
        assertEquals(Level.WARNING, THRESHOLDS.levelOf(80));
        assertEquals(Level.HIGH, THRESHOLDS.levelOf(90));
        assertEquals(Level.CRITICAL, THRESHOLDS.levelOf(95));
        assertEquals(Level.CRITICAL, THRESHOLDS.levelOf(99.9));
        assertEquals(Level.FULL, THRESHOLDS.levelOf(100));
    }

    @Test
    void unusableThresholdsFallBackToTheDefaults() {
        assertEquals("70,80,90,95", AuditStorageThresholds.parseOrDefault("95,90,80,70").toString());
        assertEquals("70,80,90,95", AuditStorageThresholds.parseOrDefault(null).toString());
        assertEquals("60,75,85,97", AuditStorageThresholds.parseOrDefault(" 60, 75,85 ,97").toString());
    }

    @Test
    void theMostSeriousLevelsKeepTheEventsSubscribersAlreadyHave() {
        assertEquals(AuditLogType.AUDIT_LOG_CAPACITY_WARNING, Level.CRITICAL.getEventType());
        assertEquals(AuditLogType.AUDIT_LOG_CAPACITY_EXCEEDED, Level.FULL.getEventType());
        assertEquals(AuditLogType.AUDIT_LOG_CAPACITY_RECOVERED, Level.NORMAL.getEventType());
    }

    @Test
    void lowerLevelsAreReportedOnlyWhenTheyAreReached() {
        assertEquals(AuditLogType.AUDIT_STORAGE_USAGE_NOTICE,
                AuditLogCapacityMonitor.eventFor(Level.NORMAL, Level.NOTICE));
        assertNull(AuditLogCapacityMonitor.eventFor(Level.NOTICE, Level.NOTICE));
        assertEquals(AuditLogType.AUDIT_STORAGE_USAGE_WARNING,
                AuditLogCapacityMonitor.eventFor(Level.NOTICE, Level.WARNING));
        // Falling back from a more serious level is not news until the store is safe again.
        assertNull(AuditLogCapacityMonitor.eventFor(Level.HIGH, Level.WARNING));
        assertEquals(AuditLogType.AUDIT_STORAGE_USAGE_WARNING,
                AuditLogCapacityMonitor.eventFor(null, Level.WARNING));
    }

    @Test
    void seriousLevelsAreReportedOnEveryCheck() {
        assertEquals(AuditLogType.AUDIT_STORAGE_USAGE_HIGH, AuditLogCapacityMonitor.eventFor(Level.HIGH, Level.HIGH));
        assertEquals(AuditLogType.AUDIT_LOG_CAPACITY_WARNING,
                AuditLogCapacityMonitor.eventFor(Level.FULL, Level.CRITICAL));
        assertEquals(AuditLogType.AUDIT_LOG_CAPACITY_EXCEEDED,
                AuditLogCapacityMonitor.eventFor(Level.FULL, Level.FULL));
    }

    @Test
    void recoveryIsReportedOnlyAfterAnAbnormalLevel() {
        assertEquals(AuditLogType.AUDIT_LOG_CAPACITY_RECOVERED,
                AuditLogCapacityMonitor.eventFor(Level.NOTICE, Level.NORMAL));
        assertNull(AuditLogCapacityMonitor.eventFor(Level.NORMAL, Level.NORMAL));
        assertNull(AuditLogCapacityMonitor.eventFor(null, Level.NORMAL));
        assertNull(AuditLogCapacityMonitor.eventFor(Level.HIGH, Level.UNKNOWN));
    }

    @Test
    void forecastsWhenAGrowingStoreFillsUp() {
        AuditLogCapacityMonitor.GrowthTracker tracker = new AuditLogCapacityMonitor.GrowthTracker();
        long start = 1_000_000_000L;
        long day = TimeUnit.DAYS.toMillis(1);
        tracker.add(start, 80 * GIB);
        assertNull(tracker.forecast(start, 80 * GIB, 100 * GIB));

        long later = start + day / 2;
        tracker.add(later, 81 * GIB);
        AuditLogCapacityMonitor.Forecast forecast = tracker.forecast(later, 81 * GIB, 100 * GIB);
        assertNotNull(forecast);
        assertEquals(2 * GIB, forecast.getBytesPerDay(), 1.0);
        assertEquals(9.5, forecast.getDaysLeft(), 0.01);
    }

    @Test
    void doesNotForecastAShrinkingStore() {
        AuditLogCapacityMonitor.GrowthTracker tracker = new AuditLogCapacityMonitor.GrowthTracker();
        long start = 1_000_000_000L;
        tracker.add(start, 50 * GIB);
        long later = start + TimeUnit.HOURS.toMillis(1);
        tracker.add(later, 40 * GIB);
        assertNull(tracker.forecast(later, 40 * GIB, 100 * GIB));
    }

    @Test
    void restoreIsRefusedOnceTheDatabaseOrBackupStorageIsHigh() {
        assertNull(snapshot(fs(Target.DB_FILESYSTEM, 89, "8:1"), fs(Target.SELECTED_BACKUP_FILESYSTEM, 10, "8:2"))
                .restoreBlockReason());
        assertNotNull(snapshot(fs(Target.DB_FILESYSTEM, 90, "8:1"), fs(Target.SELECTED_BACKUP_FILESYSTEM, 10, "8:2"))
                .restoreBlockReason());
        assertNotNull(snapshot(fs(Target.DB_FILESYSTEM, 10, "8:1"), fs(Target.SELECTED_BACKUP_FILESYSTEM, 92, "8:2"))
                .restoreBlockReason());
    }

    @Test
    void restoreIsNotRefusedWhenTheStorageCouldNotBeMeasured() {
        assertNull(snapshot(AuditStorageUsage.unavailable(Target.DB_FILESYSTEM, "", "remote"))
                .restoreBlockReason());
    }

    @Test
    void backupIsRefusedOnlyWhenItWouldMakeThingsWorse() {
        // A separate, busy volume: allowed, with a caution.
        AuditStorageSnapshot separate =
                snapshot(fs(Target.DB_FILESYSTEM, 93, "8:1"), fs(Target.SELECTED_BACKUP_FILESYSTEM, 91, "8:2"));
        assertNull(separate.backupBlockReason());
        assertNotNull(separate.backupCaution());

        // The destination itself is critical.
        assertNotNull(snapshot(fs(Target.DB_FILESYSTEM, 10, "8:1"), fs(Target.SELECTED_BACKUP_FILESYSTEM, 96, "8:2"))
                .backupBlockReason());

        // The destination shares the database file system, which is already high.
        assertNotNull(snapshot(fs(Target.DB_FILESYSTEM, 91, "8:1"), fs(Target.SELECTED_BACKUP_FILESYSTEM, 91, "8:1"))
                .backupBlockReason());

        // Sharing the file system at a safe level is allowed but pointed out.
        AuditStorageSnapshot shared =
                snapshot(fs(Target.DB_FILESYSTEM, 40, "8:1"), fs(Target.SELECTED_BACKUP_FILESYSTEM, 40, "8:1"));
        assertNull(shared.backupBlockReason());
        assertNotNull(shared.backupCaution());
    }

    @Test
    void rowsCarryEveryStoreForTheWebAdministrationTab() {
        List<String> rows = snapshot(fs(Target.DB_FILESYSTEM, 91, "8:1"),
                AuditStorageUsage.informational(Target.WAL, "/pg\twal", 5, "")).toRows();
        assertEquals(3, rows.size());
        assertTrue(rows.get(0).startsWith("META\t"));
        assertTrue(rows.get(0).endsWith("\tHIGH\t심각"));
        String[] usage = rows.get(1).split("\t", -1);
        assertEquals("USAGE", usage[0]);
        assertEquals("DB_FILESYSTEM", usage[1]);
        assertEquals("HIGH", usage[3]);
        assertEquals("91.0", usage[5]);
        // A tab inside a value must not shift the columns.
        assertEquals(10, rows.get(2).split("\t", -1).length);
    }

    @Test
    void helperOutputIsReadIntoLeveledStores() throws IOException {
        String output = "{\"filesystems\":{"
                + "\"db\":{\"path\":\"/var/lib/pgsql/data\",\"mount\":\"/var/lib/pgsql\",\"device\":\"253:3\","
                + "\"used_bytes\":90,\"available_bytes\":10,\"inode_used_percent\":1.0},"
                + "\"log\":{\"path\":\"/var/log/ovirt-engine\",\"used_bytes\":10,\"available_bytes\":90,"
                + "\"inode_used_percent\":96.0},"
                + "\"selected\":{\"path\":\"/backup\",\"error\":\"missing\"}},"
                + "\"wal\":{\"path\":\"/var/lib/pgsql/data/pg_wal\",\"size_bytes\":4096},"
                + "\"maintenance_warnings\":[\"autovacuum off\"]}";
        AuditStorageHelper.Report report = AuditStorageHelper.parse(output, THRESHOLDS, "", "/backup");
        AuditStorageSnapshot snapshot = new AuditStorageSnapshot(new Date(), 60, THRESHOLDS,
                report.getUsages(), report.getMaintenanceWarnings());

        assertEquals(Level.HIGH, snapshot.get(Target.DB_FILESYSTEM).getLevel());
        assertEquals("253:3", snapshot.get(Target.DB_FILESYSTEM).getDevice());
        // Nearly out of inodes is as serious as nearly out of space.
        assertEquals(Level.CRITICAL, snapshot.get(Target.LOG_FILESYSTEM).getLevel());
        assertEquals(4096, snapshot.get(Target.WAL).getUsedBytes());
        assertFalse(snapshot.get(Target.SELECTED_BACKUP_FILESYSTEM).isMeasured());
        assertNull(snapshot.get(Target.BACKUP_FILESYSTEM));
        assertEquals(Collections.singletonList("autovacuum off"), snapshot.getMaintenanceWarnings());
    }

    @Test
    void aRemoteDatabaseIsAnExpectedGapRatherThanAFailure() throws IOException {
        String output = "{\"filesystems\":{\"db\":{\"path\":\"\",\"error\":\"remote\",\"expected\":true},"
                + "\"log\":{\"path\":\"/var/log\",\"used_bytes\":1,\"available_bytes\":1}},"
                + "\"wal\":{\"path\":\"\",\"error\":\"remote\",\"expected\":true}}";
        AuditStorageHelper.Report report = AuditStorageHelper.parse(output, THRESHOLDS, "", "");
        AuditStorageUsage database = report.getUsages().get(0);
        assertEquals(Target.DB_FILESYSTEM, database.getTarget());
        assertFalse(database.isMeasured());
        assertTrue(database.isExpectedGap());
    }

    @Test
    void helperCommandCarriesOnlyTheDirectoriesThatAreSet() {
        assertEquals(Arrays.asList("/usr/bin/sudo", "-n", AuditStorageHelper.HELPER, "usage",
                "--log-dir", "/var/log/ovirt-engine", "--selected-dir", "/backup"),
                AuditStorageHelper.buildCommand("/var/log/ovirt-engine", "", null, " /backup "));
    }

    @Test
    void helperCommandPassesTheThresholdsTheReserveIsReleasedAt() {
        List<String> command = AuditStorageHelper.buildCommand("/var/log", "", "", "", THRESHOLDS);
        assertEquals(Arrays.asList("--thresholds", "70,80,90,95"),
                command.subList(command.size() - 2, command.size()));
    }

    @Test
    void helperOutputCarriesTheReserveAndTheWalLayout() throws IOException {
        String output = "{\"filesystems\":{\"db\":{\"path\":\"/var/lib/pgsql/data\",\"used_bytes\":96,"
                + "\"available_bytes\":4}},"
                + "\"wal\":{\"path\":\"/var/lib/pgsql/data/pg_wal\",\"size_bytes\":1,\"same_filesystem\":true},"
                + "\"reserve\":{\"state\":\"released\",\"action\":\"released\",\"path\":\"/var/lib/pgsql/r\","
                + "\"size_bytes\":2147483648,\"released_percent\":96.0}}";
        AuditStorageHelper.Report report = AuditStorageHelper.parse(output, THRESHOLDS, "", "");
        assertTrue(report.isWalOnDataFilesystem());
        assertEquals(AuditStorageHelper.Reserve.RELEASED, report.getReserve().getState());
        assertEquals("released", report.getReserve().getAction());
        assertEquals(2147483648L, report.getReserve().getSizeBytes());
        assertTrue(report.getReserve().describe().contains("2.0 GiB"));

        AuditStorageHelper.Report old = AuditStorageHelper.parse(
                "{\"filesystems\":{},\"wal\":{}}", THRESHOLDS, "", "");
        assertFalse(old.isWalOnDataFilesystem());
        assertEquals(AuditStorageHelper.Reserve.UNAVAILABLE, old.getReserve().getState());
    }

    @Test
    void capacityPlanWarnsWhenTheDiskWouldFillBeforeTheLimitPurges() {
        long limit = 10 * GIB;
        AuditStorageUsage eventTables = AuditStorageUsage.leveled(Target.EVENT_TABLES, "audit_log", GIB, limit, "",
                THRESHOLDS, "");
        // 90 GiB of 100 used: 5 GiB until the critical 95%, but 9 GiB until the limit.
        AuditLogCapacityMonitor.CapacityPlan plan = AuditLogCapacityMonitor.CapacityPlan.check(
                fs(Target.DB_FILESYSTEM, 90, ""), eventTables, limit, THRESHOLDS);
        assertNotNull(plan);
        assertEquals(6 * GIB, plan.getSuggestedBytes());
        assertTrue(plan.describe().contains("6144 MiB"));

        assertNull(AuditLogCapacityMonitor.CapacityPlan.check(
                fs(Target.DB_FILESYSTEM, 50, ""), eventTables, limit, THRESHOLDS));
        assertNull(AuditLogCapacityMonitor.CapacityPlan.check(
                fs(Target.DB_FILESYSTEM, 90, ""), eventTables, 0, THRESHOLDS));
        assertNull(AuditLogCapacityMonitor.CapacityPlan.check(
                AuditStorageUsage.unknown(Target.DB_FILESYSTEM, "", "x"), eventTables, limit, THRESHOLDS));
    }

    @Test
    void reserveIsReportedWhenReleasedAndWhenItIsBack() {
        AuditStorageHelper.Reserve released = new AuditStorageHelper.Reserve(
                AuditStorageHelper.Reserve.RELEASED, "/r", GIB, "released", "", 96.0);
        AuditStorageHelper.Reserve stillReleased = new AuditStorageHelper.Reserve(
                AuditStorageHelper.Reserve.RELEASED, "/r", GIB, "", "", 96.0);
        AuditStorageHelper.Reserve busy = new AuditStorageHelper.Reserve(
                AuditStorageHelper.Reserve.BUSY, "/r", GIB, "", "", -1);
        AuditStorageHelper.Reserve present = new AuditStorageHelper.Reserve(
                AuditStorageHelper.Reserve.PRESENT, "/r", GIB, "", "", -1);

        monitor.report(withReserve(released));
        monitor.report(withReserve(busy));
        monitor.report(withReserve(stillReleased));
        verify(auditLogDirector, times(1)).log(any(AuditLogable.class),
                eq(AuditLogType.AUDIT_STORAGE_RESERVE_RELEASED));

        monitor.report(withReserve(present));
        monitor.report(withReserve(present));
        verify(auditLogDirector, times(1)).log(any(AuditLogable.class),
                eq(AuditLogType.AUDIT_STORAGE_RESERVE_READY));
    }

    @Test
    void aReserveAlreadyInPlaceAtStartIsNotReported() {
        monitor.report(withReserve(new AuditStorageHelper.Reserve(
                AuditStorageHelper.Reserve.PRESENT, "/r", GIB, "", "", -1)));
        verify(auditLogDirector, never()).log(any(AuditLogable.class),
                eq(AuditLogType.AUDIT_STORAGE_RESERVE_READY));
    }

    @Test
    void walLayoutAndCapacityPlanAreReportedOnceEach() {
        AuditStorageUsage eventTables = AuditStorageUsage.leveled(Target.EVENT_TABLES, "audit_log", GIB,
                10240L * 1024 * 1024, "", THRESHOLDS, "");
        AuditStorageSnapshot snapshot = new AuditStorageSnapshot(new Date(), 60, THRESHOLDS,
                Arrays.asList(fs(Target.DB_FILESYSTEM, 10, ""), eventTables), Collections.emptyList(),
                AuditStorageHelper.Reserve.NONE, true, null);
        AuditStorageSnapshot tight = new AuditStorageSnapshot(new Date(), 60, THRESHOLDS,
                Arrays.asList(fs(Target.DB_FILESYSTEM, 90, ""), eventTables), Collections.emptyList(),
                AuditStorageHelper.Reserve.NONE, true, "plan");

        monitor.report(snapshot);
        monitor.report(tight);
        monitor.report(tight);
        verify(auditLogDirector, times(1)).log(any(AuditLogable.class),
                eq(AuditLogType.AUDIT_STORAGE_WAL_ON_DATA_FILESYSTEM));
        verify(auditLogDirector, times(1)).log(any(AuditLogable.class),
                eq(AuditLogType.AUDIT_STORAGE_CAPACITY_PLAN_WARNING));

        List<String> rows = tight.toRows();
        assertTrue(rows.stream().anyMatch(row -> row.startsWith("MAINTENANCE\tpg_wal")));
        assertTrue(rows.contains("MAINTENANCE\tplan"));
    }

    @Test
    void theScreenCarriesEveryStoreOnceAFullPassHasRun() {
        assertTrue(monitor.getStatus().getStorageRows().isEmpty());
    }

    /**
     * Reads the configuration, with the watched directory pointed at this test's own.
     *
     * <p>mockConfiguration() is static and runs before the temporary directory exists, so it can
     * name every value but this one; this one is stubbed here, where the directory does exist.</p>
     */
    private boolean configure() {
        doReturn(temporaryDirectory.toString())
                .when(Config.getConfigUtils())
                .getValue(ConfigValues.ENGINE_AUDIT_LOG_DIR, ConfigCommon.defaultConfigurationVersion);
        return monitor.configure();
    }

    private static AuditStorageUsage fs(Target target, long usedPercent, String device) {
        return AuditStorageUsage.leveled(target, "/" + target.name(), usedPercent * GIB, 100 * GIB, device,
                THRESHOLDS, "");
    }

    private static AuditStorageSnapshot withReserve(AuditStorageHelper.Reserve reserve) {
        return new AuditStorageSnapshot(new Date(), 60, THRESHOLDS,
                Collections.singletonList(fs(Target.DB_FILESYSTEM, 10, "")), Collections.emptyList(), reserve,
                false, null);
    }

    private static AuditStorageSnapshot snapshot(AuditStorageUsage... usages) {
        return new AuditStorageSnapshot(new Date(), 60, THRESHOLDS, Arrays.asList(usages),
                Collections.emptyList());
    }
}
