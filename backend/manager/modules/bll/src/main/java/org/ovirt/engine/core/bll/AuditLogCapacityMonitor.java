package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.Deque;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.annotation.PostConstruct;
import javax.enterprise.concurrent.ManagedScheduledExecutorService;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.ovirt.engine.core.bll.AuditStorageThresholds.Level;
import org.ovirt.engine.core.bll.AuditStorageUsage.Target;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.BackendService;
import org.ovirt.engine.core.common.businessentities.AuditLogCapacityStatus;
import org.ovirt.engine.core.common.config.Config;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogableImpl;
import org.ovirt.engine.core.dao.AuditStorageDao;
import org.ovirt.engine.core.utils.threadpool.ThreadPools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Watches every store the audit records depend on - the file system under the engine database, its
 * WAL, the engine database itself, the log file system, the engine log directory and the backup
 * storage - and reports each one as it crosses the configured usage thresholds.
 *
 * <p>The physical limit of the audit records is the file system under the PostgreSQL data
 * directory, not a number in the engine configuration, so that file system is what the levels are
 * mostly about. The levels rise through notice, warning, high and critical to full; the first two
 * are reported when they are reached, the others on every check, which the event flood regulator
 * keeps to once an hour. A store that falls back below the notice level is reported as recovered.
 *
 * <p>The engine log directory is still measured against {@code ENGINE_AUDIT_LOG_MAX_SIZE_MB}, and
 * {@link #getStatus()} still describes that directory for the capacity screen, which now also
 * carries the rows of every other store.</p>
 */
@Singleton
public class AuditLogCapacityMonitor implements BackendService {

    /** The margin the capacity screen describes the engine log directory against. */
    static final int WARNING_REMAINING_PERCENT = 5;
    static final long GROWTH_WINDOW_MILLIS = TimeUnit.HOURS.toMillis(24);
    static final long MIN_GROWTH_SPAN_MILLIS = TimeUnit.MINUTES.toMillis(10);
    private static final Logger log = LoggerFactory.getLogger(AuditLogCapacityMonitor.class);
    private static final long BYTES_PER_MIB = 1024L * 1024L;
    private static final long MILLIS_PER_DAY = TimeUnit.DAYS.toMillis(1);

    @Inject
    private AuditLogDirector auditLogDirector;

    @Inject
    private AuditStorageDao auditStorageDao;

    @Inject
    private AuditStorageHelper storageHelper;

    @Inject
    private AuditLogPurger purger;

    @Inject
    @ThreadPools(ThreadPools.ThreadPoolType.EngineScheduledThreadPool)
    private ManagedScheduledExecutorService executor;

    private final Map<Target, Level> reportedLevels = new EnumMap<>(Target.class);
    /** The last state of the emergency reserve reported, or null before the first. */
    private String reportedReserveState;
    private boolean reportedWalOnDataFilesystem;
    private boolean reportedCapacityPlanProblem;
    private final Map<Target, GrowthTracker> growth = new EnumMap<>(Target.class);
    private volatile AuditStorageSnapshot lastSnapshot;

    /**
     * The last reading of the engine log directory, for the capacity screen.
     *
     * <p>Volatile, and replaced whole rather than updated in place: it is written by the scheduled
     * pass and read by whatever request asks for it, and a reading half of which is from one pass
     * and half from the next is not a reading of anything.</p>
     */
    private volatile Reading lastReading;

    /** What the monitor was configured with, so the screen can say what the limit is. */
    private volatile Path monitoredDirectory;
    private volatile long maxBytes;
    private volatile long checkIntervalSeconds;

    @PostConstruct
    private void initialize() {
        configure();
        if (checkIntervalSeconds <= 0 || monitoredDirectory == null) {
            log.info("Audit record storage monitoring is disabled");
            return;
        }
        notifyMonitorStarted(monitoredDirectory, maxBytes / BYTES_PER_MIB, checkIntervalSeconds);
        executor.scheduleWithFixedDelay(
                this::runScheduledCheck,
                0,
                checkIntervalSeconds,
                TimeUnit.SECONDS);
    }

    /**
     * Reads what is to be watched, and how often.
     *
     * <p>The interval switches the whole monitor off when it is zero; the size limit only switches
     * off the engine log directory's own limit, since the database file system under the audit
     * records has a capacity of its own and is watched regardless.</p>
     *
     * @return whether the engine log directory is watched against its limit - false when the limit
     *         or the interval is switched off by configuration, and when the configuration cannot
     *         be read at all
     */
    boolean configure() {
        try {
            long maxSizeMiB = Config.<Long> getValue(ConfigValues.ENGINE_AUDIT_LOG_MAX_SIZE_MB);
            long interval =
                    Config.<Long> getValue(ConfigValues.ENGINE_AUDIT_LOG_CAPACITY_CHECK_INTERVAL_SECONDS);
            // Kept before the check below, so that a screen asking about capacity on a host where
            // monitoring is switched off can say that rather than saying nothing.
            monitoredDirectory = Paths.get(Config.<String> getValue(ConfigValues.ENGINE_AUDIT_LOG_DIR));
            checkIntervalSeconds = interval;
            maxBytes = maxSizeMiB > 0 ? Math.multiplyExact(maxSizeMiB, BYTES_PER_MIB) : 0;
            if (maxSizeMiB <= 0 || interval <= 0) {
                log.info("Audit log directory capacity limit is disabled");
                return false;
            }
            return true;
        } catch (RuntimeException exception) {
            log.error("Audit log capacity monitoring configuration is invalid; monitoring is disabled", exception);
            return false;
        }
    }

    private void runScheduledCheck() {
        try {
            AuditStorageSnapshot snapshot = refresh(null);
            // Outside refresh(): archiving and removing records can take minutes, and the screen and
            // the backup commands must not wait for it. Only the scheduled pass purges.
            AuditStorageUsage eventTables = snapshot.get(Target.EVENT_TABLES);
            AuditStorageUsage database = snapshot.get(Target.DB_FILESYSTEM);
            if (keepsDiskCriticalProtection(database, purger.isInDiskCriticalProtection())) {
                // The oldest records are overwritten at once, without the hour of the capacity purge.
                purger.purgeForDiskCritical(eventTables, database);
            } else if (database != null && database.isMeasured()) {
                purger.leaveDiskCritical();
            }
            if (eventTables != null && eventTables.getLevel() == Level.FULL) {
                purger.purgeForCapacity(eventTables);
            }
        } catch (RuntimeException exception) {
            log.error("Unable to check the audit record storage", exception);
        }
    }

    /**
     * Whether the oldest audit records are to be overwritten for the DB data file system: from the
     * critical level, and - once begun - until it is back under the high level, so that releasing
     * the emergency reserve or a little growth does not switch it on and off. An unmeasured file
     * system leaves things as they are.
     */
    static boolean keepsDiskCriticalProtection(AuditStorageUsage database, boolean active) {
        if (database == null || !database.isMeasured()) {
            return active;
        }
        Level level = database.getLevel();
        return level.compareTo(Level.CRITICAL) >= 0 || active && level == Level.HIGH;
    }

    /**
     * Measures every store now and reports what changed.
     *
     * @param selectedBackupDirectory
     *            a backup directory to measure as well, without reporting it, or {@code null}
     */
    public synchronized AuditStorageSnapshot refresh(String selectedBackupDirectory) {
        AuditStorageSnapshot snapshot = measure(selectedBackupDirectory, System.currentTimeMillis());
        report(snapshot);
        lastSnapshot = snapshot;
        return snapshot;
    }

    /**
     * @return what the last check measured, or {@code null} before the first check
     */
    public AuditStorageSnapshot getLastSnapshot() {
        return lastSnapshot;
    }

    AuditStorageSnapshot measure(String selectedBackupDirectory, long now) {
        AuditStorageThresholds thresholds = currentThresholds();
        String logDirectory = Config.<String> getValue(ConfigValues.ENGINE_AUDIT_LOG_DIR);
        String dataDirectory = Config.<String> getValue(ConfigValues.ENGINE_AUDIT_DB_DATA_DIR);
        String backupDirectory = Config.<String> getValue(ConfigValues.ENGINE_AUDIT_BACKUP_DIR);
        long maxSizeMiB = Config.<Long> getValue(ConfigValues.ENGINE_AUDIT_LOG_MAX_SIZE_MB);

        AuditStorageHelper.Report report = storageHelper.measure(
                logDirectory, dataDirectory, backupDirectory, selectedBackupDirectory, thresholds);
        Map<Target, AuditStorageUsage> measured = new EnumMap<>(Target.class);
        for (AuditStorageUsage usage : report.getUsages()) {
            measured.put(usage.getTarget(), usage);
        }
        measureDatabase(measured, thresholds);
        if (maxSizeMiB > 0) {
            Path directory = Paths.get(logDirectory);
            long limit = Math.multiplyExact(maxSizeMiB, BYTES_PER_MIB);
            monitoredDirectory = directory;
            maxBytes = limit;
            measured.put(Target.FILE_LOG, checkCapacity(directory, limit, thresholds));
        } else {
            maxBytes = 0;
        }

        AuditStorageHelper.Reserve reserve = report.getReserve();
        AuditStorageUsage database = measured.get(Target.DB_FILESYSTEM);
        if (database != null) {
            measured.put(Target.DB_FILESYSTEM, database.withDetail(reserve.describe()));
        }
        AuditStorageUsage wal = measured.get(Target.WAL);
        if (wal != null && report.isWalOnDataFilesystem()) {
            measured.put(Target.WAL, wal.withDetail("데이터와 같은 파일시스템 (별도 볼륨 권장)")); //$NON-NLS-1$
        }
        CapacityPlan plan = CapacityPlan.check(measured.get(Target.DB_FILESYSTEM), measured.get(Target.EVENT_TABLES),
                eventTablesLimitBytes(), thresholds);
        AuditStorageUsage eventTables = measured.get(Target.EVENT_TABLES);
        if (plan != null && eventTables != null) {
            measured.put(Target.EVENT_TABLES, eventTables.withDetail("용량 계획 경고: 한도 전에 디스크가 참")); //$NON-NLS-1$
        }

        List<AuditStorageUsage> usages = new ArrayList<>();
        for (AuditStorageUsage usage : measured.values()) {
            usages.add(withGrowth(usage, now));
        }
        return new AuditStorageSnapshot(new Date(now), checkIntervalSeconds, thresholds, usages,
                report.getMaintenanceWarnings(), reserve, report.isWalOnDataFilesystem(),
                plan == null ? null : plan.describe());
    }

    /**
     * Whether the event tables limit would be reached before the database file system fills: the
     * records are purged only at the limit, so a limit larger than the room left on the disk lets
     * the disk fill - and PostgreSQL stop - with the audit records still under it.
     */
    static final class CapacityPlan {
        private final long growthBytes;
        private final long limitBytes;
        private final long roomBytes;
        private final long suggestedBytes;
        private final int criticalPercent;

        private CapacityPlan(long growthBytes, long limitBytes, long roomBytes, long suggestedBytes,
                int criticalPercent) {
            this.growthBytes = growthBytes;
            this.limitBytes = limitBytes;
            this.roomBytes = roomBytes;
            this.suggestedBytes = suggestedBytes;
            this.criticalPercent = criticalPercent;
        }

        /**
         * @return the problem, or {@code null} when the limit is reached first, is switched off, or
         *         either store could not be measured
         */
        static CapacityPlan check(AuditStorageUsage database, AuditStorageUsage eventTables, long limitBytes,
                AuditStorageThresholds thresholds) {
            if (limitBytes <= 0 || database == null || eventTables == null || !database.isMeasured()
                    || !eventTables.isMeasured() || database.getCapacityBytes() <= 0) {
                return null;
            }
            long growth = Math.max(0, limitBytes - eventTables.getUsedBytes());
            long critical = (long) Math.floor(database.getCapacityBytes() * (thresholds.getCritical() / 100.0));
            long room = Math.max(0, critical - database.getUsedBytes());
            if (growth <= room) {
                return null;
            }
            return new CapacityPlan(growth, limitBytes, room, eventTables.getUsedBytes() + room,
                    thresholds.getCritical());
        }

        long getSuggestedBytes() {
            return suggestedBytes;
        }

        String describe() {
            return String.format(Locale.ROOT,
                    "용량 계획 경고: 이벤트 테이블은 한도(ENGINE_AUDIT_EVENT_TABLES_MAX_SIZE_MB=%d MiB)까지 %s 더 " //$NON-NLS-1$
                            + "커질 수 있지만 DB 파일시스템은 %s 뒤에 위기 수준(%d%%)에 도달합니다. 한도에 따른 정리 전에 " //$NON-NLS-1$
                            + "디스크가 차므로 한도를 %d MiB 이하로 낮추거나 저장소를 늘리십시오.", //$NON-NLS-1$
                    limitBytes / BYTES_PER_MIB, AuditStorageHelper.formatBytes(growthBytes),
                    AuditStorageHelper.formatBytes(roomBytes), criticalPercent, suggestedBytes / BYTES_PER_MIB);
        }

        void addTo(AuditLogable event) {
            event.addCustomValue("LimitMiB", Long.toString(limitBytes / BYTES_PER_MIB)); //$NON-NLS-1$
            event.addCustomValue("GrowthMiB", Long.toString(growthBytes / BYTES_PER_MIB)); //$NON-NLS-1$
            event.addCustomValue("RoomMiB", Long.toString(roomBytes / BYTES_PER_MIB)); //$NON-NLS-1$
            event.addCustomValue("CriticalPercent", Integer.toString(criticalPercent)); //$NON-NLS-1$
            event.addCustomValue("SuggestedMiB", Long.toString(suggestedBytes / BYTES_PER_MIB)); //$NON-NLS-1$
        }
    }

    private void measureDatabase(Map<Target, AuditStorageUsage> measured, AuditStorageThresholds thresholds) {
        try {
            measured.put(Target.DATABASE, AuditStorageUsage.informational(Target.DATABASE,
                    "ovirt_engine", auditStorageDao.getDatabaseSize(), "")); //$NON-NLS-1$ //$NON-NLS-2$
            measured.put(Target.EVENT_TABLES, eventTablesUsage(auditStorageDao.getEventTableUsage(),
                    eventTablesLimitBytes(), thresholds));
        } catch (RuntimeException exception) {
            log.error("Unable to measure the engine database size", exception);
            String reason = "DB 크기 조회 실패: " + exception.getMessage(); //$NON-NLS-1$
            measured.put(Target.DATABASE, AuditStorageUsage.unknown(Target.DATABASE, "ovirt_engine", reason)); //$NON-NLS-1$
            measured.put(Target.EVENT_TABLES, AuditStorageUsage.unknown(Target.EVENT_TABLES, "", reason)); //$NON-NLS-1$
        }
    }

    /**
     * The event tables against their limit. What is compared with the limit is the live data, not
     * the physical size: deleted rows leave their space in the table for new rows, so the physical
     * size does not fall when old records are removed and would keep the tables over the limit -
     * and keep removing records - long after there is room again.
     */
    static AuditStorageUsage eventTablesUsage(List<AuditStorageDao.EventTableUsage> tables, long limitBytes,
            AuditStorageThresholds thresholds) {
        long live = 0;
        long physical = 0;
        StringBuilder detail = new StringBuilder();
        for (AuditStorageDao.EventTableUsage table : tables) {
            live += table.getLiveBytes();
            physical += table.getTotalBytes();
            if (detail.length() > 0) {
                detail.append(", "); //$NON-NLS-1$
            }
            detail.append(table.getTable()).append(' ').append(AuditStorageHelper.formatBytes(table.getLiveBytes()));
        }
        detail.append("; 물리 크기 ").append(AuditStorageHelper.formatBytes(physical)) //$NON-NLS-1$
                .append(" (삭제된 행의 공간은 DB 안에서 재사용)"); //$NON-NLS-1$
        String path = "audit_log, event_*"; //$NON-NLS-1$
        if (limitBytes <= 0) {
            return AuditStorageUsage.informational(Target.EVENT_TABLES, path, live, detail.toString());
        }
        return AuditStorageUsage.leveled(Target.EVENT_TABLES, path, live, limitBytes, "", thresholds, //$NON-NLS-1$
                "ENGINE_AUDIT_EVENT_TABLES_MAX_SIZE_MB 한도; " + detail); //$NON-NLS-1$
    }

    static long eventTablesLimitBytes() {
        try {
            Long limitMiB = Config.<Long> getValue(ConfigValues.ENGINE_AUDIT_EVENT_TABLES_MAX_SIZE_MB);
            return limitMiB == null || limitMiB <= 0 ? 0 : Math.multiplyExact(limitMiB, BYTES_PER_MIB);
        } catch (RuntimeException exception) {
            return 0;
        }
    }

    private static AuditStorageThresholds currentThresholds() {
        try {
            return AuditStorageThresholds.parseOrDefault(
                    Config.<String> getValue(ConfigValues.ENGINE_AUDIT_STORAGE_THRESHOLDS));
        } catch (RuntimeException exception) {
            return AuditStorageThresholds.DEFAULT;
        }
    }

    /**
     * Measures the engine log directory against its limit, and keeps the reading for
     * {@link #getStatus()}.
     */
    AuditStorageUsage checkCapacity(Path directory, long maxBytes) {
        return checkCapacity(directory, maxBytes, currentThresholds());
    }

    private AuditStorageUsage checkCapacity(Path directory, long maxBytes, AuditStorageThresholds thresholds) {
        try {
            long usedBytes = calculateDirectorySize(directory);
            lastReading = new Reading(usedBytes, Instant.now(), null);
            return AuditStorageUsage.leveled(Target.FILE_LOG, directory.toString(), usedBytes, maxBytes, "", //$NON-NLS-1$
                    thresholds, "ENGINE_AUDIT_LOG_MAX_SIZE_MB 한도"); //$NON-NLS-1$
        } catch (IOException | RuntimeException exception) {
            // Remembered as a reading that could not be taken. Leaving the previous one standing
            // would have the screen showing a figure from before the directory became unreadable,
            // with nothing to say that it is no longer being measured.
            String reason = describe(exception);
            lastReading = new Reading(0, Instant.now(), reason);
            log.error("Unable to measure audit log capacity in {}", directory, exception);
            return AuditStorageUsage.unknown(Target.FILE_LOG, directory.toString(), reason);
        }
    }

    /**
     * The engine log directory as the capacity screen shows it, together with the rows of every
     * store the last full pass measured.
     *
     * <p>Answers even when the monitor is not running, because "not being measured" is the state an
     * administrator most needs to be told about and the one that otherwise shows as an empty
     * screen. When the directory has not been measured yet - the engine has just started, or the
     * first pass has not finished - it is measured here so that the screen is not blank for the
     * first minute. The other stores are not: measuring them runs the root helper, which the
     * screen asks for explicitly.</p>
     */
    public AuditLogCapacityStatus getStatus() {
        AuditLogCapacityStatus status = new AuditLogCapacityStatus();
        AuditStorageSnapshot snapshot = lastSnapshot;
        if (snapshot != null) {
            status.setStorageRows(new ArrayList<>(snapshot.toRows()));
        }
        Path directory = monitoredDirectory;
        long limit = maxBytes;
        status.setDirectory(directory == null ? "" : directory.toString()); //$NON-NLS-1$
        status.setMaxBytes(limit);
        status.setCheckIntervalSeconds(checkIntervalSeconds);
        status.setWarningRemainingPercent(WARNING_REMAINING_PERCENT);

        if (directory == null || limit <= 0 || checkIntervalSeconds <= 0) {
            status.setState(AuditLogCapacityStatus.State.DISABLED);
            return status;
        }

        Reading reading = lastReading;
        if (reading == null) {
            // Nothing has been measured yet. Measuring here costs one walk of the directory, and
            // the alternative is a screen that says nothing at all until the first pass lands.
            reading = measureNow(directory);
            status.setMeasuredOnDemand(true);
        }
        status.setMeasuredAt(Date.from(reading.takenAt));
        if (reading.failure != null) {
            status.setState(AuditLogCapacityStatus.State.UNAVAILABLE);
            status.setUnavailableReason(reading.failure);
            return status;
        }
        status.setUsedBytes(reading.usedBytes);
        status.setRemainingPercent(remainingPercent(reading.usedBytes, limit));
        status.setState(capacityState(reading.usedBytes, limit));
        return status;
    }

    private Reading measureNow(Path directory) {
        try {
            Reading reading = new Reading(calculateDirectorySize(directory), Instant.now(), null);
            // Kept, so that a second screen opened a moment later does not walk the directory
            // again; the scheduled pass replaces it as usual.
            lastReading = reading;
            return reading;
        } catch (IOException | RuntimeException exception) {
            log.error("Unable to measure audit log capacity in {}", directory, exception);
            return new Reading(0, Instant.now(), describe(exception));
        }
    }

    static AuditLogCapacityStatus.State capacityState(long usedBytes, long maxBytes) {
        if (usedBytes >= maxBytes) {
            return AuditLogCapacityStatus.State.EXCEEDED;
        }
        if (isWithinWarningRange(usedBytes, maxBytes, WARNING_REMAINING_PERCENT)) {
            return AuditLogCapacityStatus.State.WARNING;
        }
        return AuditLogCapacityStatus.State.NORMAL;
    }

    static boolean isWithinWarningRange(long usedBytes, long maxBytes, int remainingThresholdPercent) {
        return maxBytes > 0 && usedBytes < maxBytes
                && remainingPercent(usedBytes, maxBytes) <= remainingThresholdPercent;
    }

    static long remainingPercent(long usedBytes, long maxBytes) {
        if (maxBytes <= 0 || usedBytes >= maxBytes) {
            return 0;
        }
        return ((maxBytes - usedBytes) * 100) / maxBytes;
    }

    /**
     * Why a reading could not be taken, in a line a screen can show.
     *
     * <p>The class name as well as the message: several of the messages this can carry are a bare
     * path, which on its own does not say what went wrong with it.</p>
     */
    private static String describe(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isEmpty()
                ? exception.getClass().getSimpleName()
                : exception.getClass().getSimpleName() + ": " + message; //$NON-NLS-1$
    }

    /** One measurement of the engine log directory, or one attempt at it. */
    private static final class Reading {
        private final long usedBytes;
        private final Instant takenAt;

        /** Why it could not be taken, or null when it was. */
        private final String failure;

        private Reading(long usedBytes, Instant takenAt, String failure) {
            this.usedBytes = usedBytes;
            this.takenAt = takenAt;
            this.failure = failure;
        }
    }

    private AuditStorageUsage withGrowth(AuditStorageUsage usage, long now) {
        if (!usage.isMeasured() || usage.getTarget() == Target.SELECTED_BACKUP_FILESYSTEM) {
            return usage;
        }
        GrowthTracker tracker = growth.computeIfAbsent(usage.getTarget(), target -> new GrowthTracker());
        tracker.add(now, usage.getUsedBytes());
        Forecast forecast = tracker.forecast(now, usage.getUsedBytes(), usage.getCapacityBytes());
        return forecast == null ? usage : usage.withDetail(forecast.describe());
    }

    void report(AuditStorageSnapshot snapshot) {
        for (AuditStorageUsage usage : snapshot.getUsages()) {
            Target target = usage.getTarget();
            if (!target.isReported()) {
                continue;
            }
            if (!usage.isMeasured()) {
                if (!usage.isExpectedGap()) {
                    AuditLogable event = targetEvent(usage);
                    event.addCustomValue("Reason", usage.getDetail()); //$NON-NLS-1$
                    log(event, AuditLogType.AUDIT_STORAGE_MEASUREMENT_FAILED);
                }
                continue;
            }
            AuditLogType type = eventFor(reportedLevels.get(target), usage.getLevel());
            reportedLevels.put(target, usage.getLevel());
            if (type != null) {
                log(usageEvent(usage, snapshot), type);
            }
        }
        if (!snapshot.getMaintenanceWarnings().isEmpty()) {
            AuditLogable event = new AuditLogableImpl();
            event.setCustomId("DB_MAINTENANCE"); //$NON-NLS-1$
            event.addCustomValue("Reason", String.join("; ", snapshot.getMaintenanceWarnings())); //$NON-NLS-1$ //$NON-NLS-2$
            log(event, AuditLogType.AUDIT_STORAGE_DB_MAINTENANCE_WARNING);
        }
        reportReserve(snapshot);
        reportLayout(snapshot);
    }

    /**
     * Reports the emergency reserve when it is released, when it is in place again, and when it
     * cannot be kept. A run that did not see it - another check held it, or the database is on
     * another server - leaves the last state standing.
     */
    private void reportReserve(AuditStorageSnapshot snapshot) {
        AuditStorageHelper.Reserve reserve = snapshot.getReserve();
        String state = reserve.getState();
        if (AuditStorageHelper.Reserve.BUSY.equals(state) || AuditStorageHelper.Reserve.UNAVAILABLE.equals(state)) {
            return;
        }
        String previous = reportedReserveState;
        reportedReserveState = state;
        AuditLogable event = new AuditLogableImpl();
        event.setCustomId("DB_RESERVE"); //$NON-NLS-1$
        event.addCustomValue("Path", reserve.getPath()); //$NON-NLS-1$
        event.addCustomValue("SizeMiB", Long.toString(reserve.getSizeBytes() / BYTES_PER_MIB)); //$NON-NLS-1$
        if (AuditStorageHelper.Reserve.RELEASED.equals(state)) {
            if (!state.equals(previous)) {
                double percent = reserve.getReleasedPercent();
                AuditStorageUsage database = snapshot.get(Target.DB_FILESYSTEM);
                if (percent < 0 && database != null) {
                    percent = database.getUsedPercent();
                }
                event.addCustomValue("UsedPercent", //$NON-NLS-1$
                        percent < 0 ? "-" : AuditStorageSnapshot.formatPercent(percent)); //$NON-NLS-1$
                log(event, AuditLogType.AUDIT_STORAGE_RESERVE_RELEASED);
            }
        } else if (AuditStorageHelper.Reserve.PRESENT.equals(state)) {
            if (!reserve.getAction().isEmpty() || AuditStorageHelper.Reserve.RELEASED.equals(previous)) {
                log(event, AuditLogType.AUDIT_STORAGE_RESERVE_READY);
            }
        } else if ((AuditStorageHelper.Reserve.INSUFFICIENT.equals(state)
                || AuditStorageHelper.Reserve.ERROR.equals(state)) && !state.equals(previous)) {
            event.addCustomValue("Reason", reserve.getDetail()); //$NON-NLS-1$
            log(event, AuditLogType.AUDIT_STORAGE_RESERVE_UNAVAILABLE);
        }
    }

    /**
     * Reports, once each time they appear, a WAL on the data file system and an event tables limit
     * the disk would not reach.
     */
    private void reportLayout(AuditStorageSnapshot snapshot) {
        AuditStorageUsage database = snapshot.get(Target.DB_FILESYSTEM);
        if (database != null && database.isMeasured()) {
            boolean shared = snapshot.isWalOnDataFilesystem();
            if (shared && !reportedWalOnDataFilesystem) {
                AuditLogable event = new AuditLogableImpl();
                event.setCustomId("DB_WAL_LAYOUT"); //$NON-NLS-1$
                AuditStorageUsage wal = snapshot.get(Target.WAL);
                event.addCustomValue("Path", wal == null ? "pg_wal" : wal.getPath()); //$NON-NLS-1$ //$NON-NLS-2$
                log(event, AuditLogType.AUDIT_STORAGE_WAL_ON_DATA_FILESYSTEM);
            }
            reportedWalOnDataFilesystem = shared;
        }
        CapacityPlan plan = CapacityPlan.check(database, snapshot.get(Target.EVENT_TABLES), eventTablesLimitBytes(),
                snapshot.getThresholds());
        if (plan != null && !reportedCapacityPlanProblem) {
            AuditLogable event = new AuditLogableImpl();
            event.setCustomId("DB_CAPACITY_PLAN"); //$NON-NLS-1$
            plan.addTo(event);
            log(event, AuditLogType.AUDIT_STORAGE_CAPACITY_PLAN_WARNING);
        }
        if (database != null && database.isMeasured()) {
            reportedCapacityPlanProblem = plan != null;
        }
    }

    /**
     * Decides what, if anything, is reported for a store that was at {@code previous} and is now
     * at {@code current}.
     *
     * @param previous
     *            the level last reported, or {@code null} when the store has not been measured yet
     */
    static AuditLogType eventFor(Level previous, Level current) {
        if (current == Level.UNKNOWN) {
            return null;
        }
        if (current == Level.NORMAL) {
            return previous != null && previous.isAbnormal() ? AuditLogType.AUDIT_LOG_CAPACITY_RECOVERED : null;
        }
        if (current.isRepeated() || previous == null || current.compareTo(previous) > 0) {
            return current.getEventType();
        }
        return null;
    }

    private AuditLogable targetEvent(AuditStorageUsage usage) {
        AuditLogable event = new AuditLogableImpl();
        // The flood regulator keys on the custom id, so each store is throttled on its own.
        event.setCustomId(usage.getTarget().name());
        event.addCustomValue("Target", usage.getTarget().getLabel()); //$NON-NLS-1$
        event.addCustomValue("Path", usage.getPath()); //$NON-NLS-1$
        return event;
    }

    private AuditLogable usageEvent(AuditStorageUsage usage, AuditStorageSnapshot snapshot) {
        AuditLogable event = targetEvent(usage);
        event.addCustomValue("UsedSizeMiB", Long.toString(usage.getUsedBytes() / BYTES_PER_MIB)); //$NON-NLS-1$
        event.addCustomValue("MaxSizeMiB", Long.toString(usage.getCapacityBytes() / BYTES_PER_MIB)); //$NON-NLS-1$
        event.addCustomValue("UsedPercent", AuditStorageSnapshot.formatPercent(usage.getUsedPercent())); //$NON-NLS-1$
        event.addCustomValue("RemainingPercent", Long.toString(usage.getRemainingPercent())); //$NON-NLS-1$
        event.addCustomValue("Forecast", forecastText( //$NON-NLS-1$
                growth.get(usage.getTarget()),
                snapshot.getMeasuredAt().getTime(),
                usage.getUsedBytes(),
                usage.getCapacityBytes()));
        return event;
    }

    /**
     * What the event says about where the store is heading.
     *
     * <p>Never empty: the message resolver writes an empty value as {@code <UNKNOWN>}, which is
     * how "no forecast yet" used to read in the event list.</p>
     */
    static String forecastText(GrowthTracker tracker, long now, long usedBytes, long capacityBytes) {
        if (tracker == null || !tracker.watchedLongEnough(now)) {
            return ", growth trend not available yet"; //$NON-NLS-1$
        }
        Forecast forecast = tracker.forecast(now, usedBytes, capacityBytes);
        return forecast == null
                ? ", not growing" //$NON-NLS-1$
                : forecast.describeForEvent();
    }

    private void log(AuditLogable event, AuditLogType type) {
        try {
            auditLogDirector.log(event, type);
        } catch (RuntimeException exception) {
            // Reporting one store must not keep the others from being reported.
            log.error("Unable to report audit record storage event {}", type, exception);
        }
    }

    private void notifyMonitorStarted(Path directory, long maxSizeMiB, long checkIntervalSeconds) {
        AuditLogable event = new AuditLogableImpl();
        event.addCustomValue("Directory", directory.toString()); //$NON-NLS-1$
        event.addCustomValue("MaxSizeMiB", Long.toString(maxSizeMiB)); //$NON-NLS-1$
        event.addCustomValue("CheckIntervalSeconds", Long.toString(checkIntervalSeconds)); //$NON-NLS-1$
        try {
            auditLogDirector.log(event, AuditLogType.AUDIT_LOG_CAPACITY_MONITOR_STARTED);
        } catch (RuntimeException exception) {
            // A diagnostic event must never prevent the capacity check from running.
            log.error("Unable to report that audit log capacity monitoring started", exception);
        }
    }

    static long calculateDirectorySize(Path directory) throws IOException {
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Audit log directory does not exist: " + directory); //$NON-NLS-1$
        }
        AtomicLong size = new AtomicLong();
        Files.walkFileTree(directory, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) {
                if (attributes.isRegularFile()) {
                    size.addAndGet(attributes.size());
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exception) throws IOException {
                if (directory.equals(file)) {
                    throw exception;
                }
                // Some children (for example the root-owned setup directory) are
                // intentionally inaccessible to the engine service account. They
                // must not prevent the remaining audit logs from being measured.
                log.debug("Skipping inaccessible path while measuring audit log capacity: {}", file, exception);
                return FileVisitResult.CONTINUE;
            }
        });
        return size.get();
    }

    /**
     * When a store is expected to be full, going by how fast it grew over the last day.
     */
    static final class Forecast {
        private final double bytesPerDay;
        private final long fullAtMillis;
        private final long now;

        Forecast(double bytesPerDay, long fullAtMillis, long now) {
            this.bytesPerDay = bytesPerDay;
            this.fullAtMillis = fullAtMillis;
            this.now = now;
        }

        double getBytesPerDay() {
            return bytesPerDay;
        }

        long getFullAtMillis() {
            return fullAtMillis;
        }

        double getDaysLeft() {
            return (fullAtMillis - now) / (double) MILLIS_PER_DAY;
        }

        String describe() {
            return String.format(Locale.ROOT, "증가율 %s/일, 예상 포화 %s (약 %.1f일 후)", //$NON-NLS-1$
                    AuditStorageHelper.formatBytes(Math.round(bytesPerDay)), formatTime(), getDaysLeft());
        }

        String describeForEvent() {
            return String.format(Locale.ROOT, ", growing %s/day, expected to be full around %s (%.1f days)", //$NON-NLS-1$
                    AuditStorageHelper.formatBytes(Math.round(bytesPerDay)), formatTime(), getDaysLeft());
        }

        private String formatTime() {
            return new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.ROOT).format(new Date(fullAtMillis)); //$NON-NLS-1$
        }
    }

    /**
     * The usage of one store over the last day, kept in memory. It starts again when the engine
     * restarts, so a forecast appears once the store has been watched for a few minutes.
     */
    static final class GrowthTracker {
        private final Deque<long[]> samples = new ArrayDeque<>();

        void add(long now, long usedBytes) {
            samples.addLast(new long[] { now, usedBytes });
            while (samples.size() > 1 && now - samples.peekFirst()[0] > GROWTH_WINDOW_MILLIS) {
                samples.removeFirst();
            }
        }

        boolean watchedLongEnough(long now) {
            return !samples.isEmpty() && now - samples.peekFirst()[0] >= MIN_GROWTH_SPAN_MILLIS;
        }

        /**
         * @return when the store fills up at its present rate, or {@code null} when it is not
         *         growing or has not been watched for long enough to tell
         */
        Forecast forecast(long now, long usedBytes, long capacityBytes) {
            if (samples.isEmpty() || capacityBytes <= 0) {
                return null;
            }
            long[] oldest = samples.peekFirst();
            long span = now - oldest[0];
            if (span < MIN_GROWTH_SPAN_MILLIS) {
                return null;
            }
            double bytesPerMilli = (usedBytes - oldest[1]) / (double) span;
            if (bytesPerMilli <= 0) {
                return null;
            }
            long remaining = Math.max(0, capacityBytes - usedBytes);
            long fullAt = now + (long) (remaining / bytesPerMilli);
            return new Forecast(bytesPerMilli * MILLIS_PER_DAY, fullAt, now);
        }
    }
}
