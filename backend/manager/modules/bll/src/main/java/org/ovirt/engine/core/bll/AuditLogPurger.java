package org.ovirt.engine.core.bll;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;
import java.util.function.LongFunction;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.config.Config;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogableImpl;
import org.ovirt.engine.core.dao.AuditStorageDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Removes the oldest audit records, and never without archiving them first.
 *
 * <p>Two things remove audit records: the daily cleanup, which removes what is older than the
 * retention period ({@code AuditLogAgingThreshold}, 90 days), and the capacity purge, which
 * removes the oldest records once the event tables reach {@code ENGINE_AUDIT_EVENT_TABLES_MAX_SIZE_MB}
 * until they are back at {@code ENGINE_AUDIT_CAPACITY_PURGE_TARGET_PERCENT} of it - but never a
 * record younger than {@code ENGINE_AUDIT_CAPACITY_PURGE_MIN_RETENTION_DAYS} (30 days).</p>
 *
 * <p>Both go through the root helper, which copies the records to a compressed CSV archive and
 * deletes exactly those records in one transaction, so a failure removes nothing. Every removal
 * and every refusal is itself recorded as an event.</p>
 */
@Singleton
public class AuditLogPurger {

    static final String SUDO_COMMAND = "/usr/bin/sudo"; //$NON-NLS-1$
    static final String BACKUP_HELPER = "/usr/share/ovirt-engine/bin/audit-log-backup.py"; //$NON-NLS-1$
    static final String DEFAULT_ARCHIVE_DIR = "/var/lib/ovirt-engine-backup/audit-log-purged"; //$NON-NLS-1$
    static final long MIN_CAPACITY_PURGE_INTERVAL_MILLIS = TimeUnit.HOURS.toMillis(1);
    /**
     * How often the oldest records are removed while the DB file system is at the critical level.
     * The first removal is at once; the hour of the capacity purge does not apply.
     */
    static final long CRITICAL_PURGE_INTERVAL_MILLIS = TimeUnit.MINUTES.toMillis(5);
    /** The room made inside the event tables on reaching the critical level: 5% of them, within these. */
    static final int CRITICAL_HEADROOM_PERCENT = 5;
    static final long MIN_CRITICAL_HEADROOM_BYTES = 16L * 1024L * 1024L;
    static final long MAX_CRITICAL_HEADROOM_BYTES = 256L * 1024L * 1024L;
    private static final long HELPER_TIMEOUT_MINUTES = 35;
    private static final long BYTES_PER_MIB = 1024L * 1024L;
    private static final Logger log = LoggerFactory.getLogger(AuditLogPurger.class);

    /** Why records are being removed, as the event says it. */
    public enum Reason {
        RETENTION("older than the retention period"), //$NON-NLS-1$
        CAPACITY("the event tables reached their limit"), //$NON-NLS-1$
        DISK_CRITICAL("the DB filesystem reached the critical level; new records reuse the space of the oldest"); //$NON-NLS-1$

        private final String text;

        Reason(String text) {
            this.text = text;
        }

        public String getText() {
            return text;
        }
    }

    /** What a capacity purge is to remove. */
    static final class Plan {
        private final Date cutoff;
        private final boolean limitedByRetention;

        Plan(Date cutoff, boolean limitedByRetention) {
            this.cutoff = cutoff;
            this.limitedByRetention = limitedByRetention;
        }

        Date getCutoff() {
            return cutoff;
        }

        boolean isLimitedByRetention() {
            return limitedByRetention;
        }
    }

    /** What the helper did. */
    static final class Result {
        private final boolean succeeded;
        private final long deleted;
        private final String archive;
        private final String vacuumFailure;
        private final String error;
        private final String archiveSkipped;

        Result(boolean succeeded, long deleted, String archive, String vacuumFailure, String error) {
            this(succeeded, deleted, archive, vacuumFailure, error, null);
        }

        Result(boolean succeeded, long deleted, String archive, String vacuumFailure, String error,
                String archiveSkipped) {
            this.succeeded = succeeded;
            this.deleted = deleted;
            this.archive = archive;
            this.vacuumFailure = vacuumFailure;
            this.error = error;
            this.archiveSkipped = archiveSkipped;
        }

        /** Why the records were removed without an archive, or {@code null} when they were archived. */
        String getArchiveSkipped() {
            return archiveSkipped;
        }

        boolean isSucceeded() {
            return succeeded;
        }

        long getDeleted() {
            return deleted;
        }

        String getArchive() {
            return archive;
        }

        String getVacuumFailure() {
            return vacuumFailure;
        }

        String getError() {
            return error;
        }
    }

    @Inject
    private AuditStorageDao auditStorageDao;

    @Inject
    private AuditLogDirector auditLogDirector;

    private volatile long lastCapacityPurgeAt;

    /** What the event tables are kept under while the DB file system is critical; -1 when it is not. */
    private volatile long criticalCeilingBytes = -1;
    private volatile long lastCriticalPurgeAt;
    private volatile boolean criticalBlockedReported;

    /**
     * Removes the audit records logged before the cutoff, having archived them. Does nothing when
     * there are none.
     */
    public void purgeOlderThan(Date cutoff, Reason reason) {
        purgeOlderThan(cutoff, reason, null);
    }

    /**
     * @param skipArchiveOnFilesystemOf
     *            the DB data directory, for a purge at the critical level: an archive location on
     *            its file system is not written, and the records are removed without one
     */
    public synchronized void purgeOlderThan(Date cutoff, Reason reason, String skipArchiveOnFilesystemOf) {
        long candidates = auditStorageDao.countAuditLogOlderThan(cutoff);
        if (candidates == 0) {
            log.debug("No audit records logged before {} to remove", cutoff);
            return;
        }
        log.info("Archiving and removing {} audit records logged before {} ({})", candidates, cutoff,
                reason.getText());
        Result result = runHelper(archiveDirectory(), cutoff, skipArchiveOnFilesystemOf);
        AuditLogable event = new AuditLogableImpl();
        event.setCustomId("AUDIT_LOG_PURGE_" + reason.name()); //$NON-NLS-1$
        event.addCustomValue("Cutoff", formatTime(cutoff)); //$NON-NLS-1$
        event.addCustomValue("Reason", reason.getText()); //$NON-NLS-1$
        event.addCustomValue("Notice", notice(reason)); //$NON-NLS-1$
        if (!result.isSucceeded()) {
            log.error("Audit records logged before {} were not removed: {}", cutoff, result.getError());
            event.addCustomValue("Error", result.getError()); //$NON-NLS-1$
            report(event, AuditLogType.AUDIT_LOG_RECORDS_PURGE_FAILED);
            return;
        }
        if (result.getDeleted() == 0) {
            return;
        }
        event.addCustomValue("Count", Long.toString(result.getDeleted())); //$NON-NLS-1$
        event.addCustomValue("Archive", result.getArchive()); //$NON-NLS-1$
        // Never empty: the message resolver writes an empty value as <UNKNOWN>.
        event.addCustomValue("VacuumNote", result.getVacuumFailure() == null //$NON-NLS-1$
                ? " The freed space is reused by new records." //$NON-NLS-1$
                : " VACUUM failed and the freed space is reused only after autovacuum runs: " //$NON-NLS-1$
                        + result.getVacuumFailure());
        if (result.getArchiveSkipped() != null) {
            log.warn("Audit records logged before {} were removed without an archive: {}", cutoff,
                    result.getArchiveSkipped());
            event.addCustomValue("ArchiveNote", result.getArchiveSkipped()); //$NON-NLS-1$
            report(event, AuditLogType.AUDIT_LOG_RECORDS_PURGED_WITHOUT_ARCHIVE);
            return;
        }
        report(event, AuditLogType.AUDIT_LOG_RECORDS_PURGED);
    }

    /**
     * What the purge event begins with, so that the event list says in its own words that the
     * audit records were acted on: {@code [주의] 감사로그 용량 초과로 대응 작업을 진행했습니다.}
     */
    static String notice(Reason reason) {
        return reason == Reason.RETENTION
                ? "[주의] 감사로그 보존기간 경과로 정리 작업을 진행했습니다." //$NON-NLS-1$
                : "[주의] 감사로그 용량 초과로 대응 작업을 진행했습니다."; //$NON-NLS-1$
    }

    /**
     * Brings the event tables back under their limit by removing the oldest audit records, if the
     * purge is enabled, has not run in the last hour and the minimum retention leaves anything to
     * remove.
     *
     * @param eventTables
     *            the event tables as the monitor just measured them, at or over their limit
     */
    public void purgeForCapacity(AuditStorageUsage eventTables) {
        if (!isCapacityPurgeEnabled()) {
            return;
        }
        long now = System.currentTimeMillis();
        // The live size is an estimate; a purge that fell short is given an hour for the
        // statistics to settle rather than being repeated on every check.
        if (now - lastCapacityPurgeAt < MIN_CAPACITY_PURGE_INTERVAL_MILLIS) {
            return;
        }
        lastCapacityPurgeAt = now;
        int retentionDays = configInt(ConfigValues.ENGINE_AUDIT_CAPACITY_PURGE_MIN_RETENTION_DAYS, 30);
        int targetPercent = configInt(ConfigValues.ENGINE_AUDIT_CAPACITY_PURGE_TARGET_PERCENT, 80);
        try {
            AuditStorageDao.EventTableUsage auditLog = auditStorageDao.getEventTableUsage().stream()
                    .filter(table -> "audit_log".equals(table.getTable())) //$NON-NLS-1$
                    .findFirst()
                    .orElse(null);
            if (auditLog == null) {
                return;
            }
            Plan plan = planCapacityPurge(eventTables.getUsedBytes(), eventTables.getCapacityBytes(), targetPercent,
                    auditLog.getLiveBytes(), auditLog.getLiveRows(), auditStorageDao::getAuditLogTimeAfterOldest,
                    new Date(now), retentionDays);
            if (plan == null) {
                return;
            }
            if (auditStorageDao.countAuditLogOlderThan(plan.getCutoff()) == 0) {
                AuditLogable event = new AuditLogableImpl();
                event.setCustomId("AUDIT_LOG_PURGE_CAPACITY"); //$NON-NLS-1$
                event.addCustomValue("UsedSizeMiB", Long.toString(eventTables.getUsedBytes() / BYTES_PER_MIB)); //$NON-NLS-1$
                event.addCustomValue("MaxSizeMiB", Long.toString(eventTables.getCapacityBytes() / BYTES_PER_MIB)); //$NON-NLS-1$
                event.addCustomValue("RetentionDays", Integer.toString(retentionDays)); //$NON-NLS-1$
                report(event, AuditLogType.AUDIT_LOG_CAPACITY_PURGE_BLOCKED);
                return;
            }
            purgeOlderThan(plan.getCutoff(), Reason.CAPACITY);
        } catch (RuntimeException exception) {
            log.error("Unable to purge audit records for capacity", exception);
        }
    }

    /**
     * Keeps the audit records from taking more of a DB file system at the critical level.
     *
     * <p>Removing records does not give the disk back - the space stays with the table - but new
     * records reuse it, so the event tables stop growing: the oldest records are overwritten. On
     * reaching the critical level a little room ({@value #CRITICAL_HEADROOM_PERCENT}% of the event
     * tables) is made at once, without the hour of the capacity purge; after that, every
     * {@link #CRITICAL_PURGE_INTERVAL_MILLIS} minutes, whatever the tables grew beyond that is
     * removed again. The minimum retention still holds. An archive location on the DB file
     * system itself is not written: the records are removed without one, and the event says so.</p>
     *
     * @param eventTables
     *            the event tables as just measured
     * @param database
     *            the DB data file system as just measured, at the critical level or above
     */
    public void purgeForDiskCritical(AuditStorageUsage eventTables, AuditStorageUsage database) {
        if (!isCapacityPurgeEnabled() || eventTables == null || !eventTables.isMeasured()) {
            return;
        }
        long now = System.currentTimeMillis();
        long live = eventTables.getUsedBytes();
        if (criticalCeilingBytes < 0) {
            criticalCeilingBytes = criticalCeiling(live);
            log.warn("DB filesystem reached the critical level; keeping the event tables under {} bytes "
                    + "by removing the oldest audit records", criticalCeilingBytes);
        } else if (now - lastCriticalPurgeAt < CRITICAL_PURGE_INTERVAL_MILLIS) {
            return;
        }
        long excess = live - criticalCeilingBytes;
        if (excess <= 0) {
            return;
        }
        lastCriticalPurgeAt = now;
        int retentionDays = configInt(ConfigValues.ENGINE_AUDIT_CAPACITY_PURGE_MIN_RETENTION_DAYS, 30);
        try {
            AuditStorageDao.EventTableUsage auditLog = auditStorageDao.getEventTableUsage().stream()
                    .filter(table -> "audit_log".equals(table.getTable())) //$NON-NLS-1$
                    .findFirst()
                    .orElse(null);
            if (auditLog == null) {
                return;
            }
            Plan plan = planPurge(excess, auditLog.getLiveBytes(), auditLog.getLiveRows(),
                    auditStorageDao::getAuditLogTimeAfterOldest, new Date(now), retentionDays);
            if (plan == null) {
                return;
            }
            if (auditStorageDao.countAuditLogOlderThan(plan.getCutoff()) == 0) {
                if (!criticalBlockedReported) {
                    criticalBlockedReported = true;
                    AuditLogable event = new AuditLogableImpl();
                    event.setCustomId("AUDIT_LOG_PURGE_DISK_CRITICAL"); //$NON-NLS-1$
                    event.addCustomValue("UsedPercent", //$NON-NLS-1$
                            database == null ? "-" : AuditStorageSnapshot.formatPercent(database.getUsedPercent())); //$NON-NLS-1$
                    event.addCustomValue("RetentionDays", Integer.toString(retentionDays)); //$NON-NLS-1$
                    report(event, AuditLogType.AUDIT_LOG_CRITICAL_PURGE_BLOCKED);
                }
                return;
            }
            purgeOlderThan(plan.getCutoff(), Reason.DISK_CRITICAL, database == null ? null : database.getPath());
        } catch (RuntimeException exception) {
            log.error("Unable to purge audit records at the critical DB filesystem level", exception);
        }
    }

    /** The DB file system is below the critical level again: back to the ordinary rules. */
    public void leaveDiskCritical() {
        if (criticalCeilingBytes >= 0) {
            log.info("DB filesystem is below the critical level again; audit records are no longer "
                    + "removed for it");
        }
        criticalCeilingBytes = -1;
        lastCriticalPurgeAt = 0;
        criticalBlockedReported = false;
    }

    boolean isInDiskCriticalProtection() {
        return criticalCeilingBytes >= 0;
    }

    /** What the event tables are held under: their size less the room made on reaching the level. */
    static long criticalCeiling(long liveBytes) {
        long headroom = Math.max(MIN_CRITICAL_HEADROOM_BYTES,
                Math.min(MAX_CRITICAL_HEADROOM_BYTES, liveBytes / 100 * CRITICAL_HEADROOM_PERCENT));
        return Math.max(0, liveBytes - headroom);
    }

    /**
     * Decides how far back a capacity purge removes: far enough to bring the event tables down to
     * the target share of their limit, going by the average size of an audit record, but never past
     * the minimum retention.
     *
     * @param timeAfterOldest
     *            the time of the record that has the given number of records older than it, or
     *            {@code null} when there are no more records than that
     * @return the plan, or {@code null} when the tables are already under the target
     */
    static Plan planCapacityPurge(long liveBytes, long limitBytes, int targetPercent, long auditLogLiveBytes,
            long auditLogRows, LongFunction<Date> timeAfterOldest, Date now, int minRetentionDays) {
        if (limitBytes <= 0) {
            return null;
        }
        long target = limitBytes / 100 * targetPercent;
        return planPurge(liveBytes - target, auditLogLiveBytes, auditLogRows, timeAfterOldest, now,
                minRetentionDays);
    }

    /**
     * How far back to remove so that about {@code excessBytes} of audit records go, the oldest
     * first, but never past the minimum retention.
     *
     * @return the plan, or {@code null} when there is nothing to remove
     */
    static Plan planPurge(long excess, long auditLogLiveBytes, long auditLogRows, LongFunction<Date> timeAfterOldest,
            Date now, int minRetentionDays) {
        if (excess <= 0 || auditLogRows <= 0 || auditLogLiveBytes <= 0) {
            return null;
        }
        double bytesPerRecord = (double) auditLogLiveBytes / auditLogRows;
        long records = (long) Math.ceil(excess / bytesPerRecord);
        Date cutoff = timeAfterOldest.apply(records);
        if (cutoff == null) {
            cutoff = now;
        }
        Date retained = new Date(now.getTime() - TimeUnit.DAYS.toMillis(minRetentionDays));
        if (cutoff.after(retained)) {
            return new Plan(retained, true);
        }
        return new Plan(cutoff, false);
    }

    static List<String> helperCommand(String directory, Date cutoff, String skipArchiveOnFilesystemOf) {
        List<String> command = new ArrayList<>(Arrays.asList(SUDO_COMMAND, "-n", BACKUP_HELPER, "purge", //$NON-NLS-1$ //$NON-NLS-2$
                directory, Instant.ofEpochMilli(cutoff.getTime()).toString()));
        if (skipArchiveOnFilesystemOf != null && !skipArchiveOnFilesystemOf.trim().isEmpty()) {
            command.add("--skip-archive-on-filesystem-of"); //$NON-NLS-1$
            command.add(skipArchiveOnFilesystemOf.trim());
        }
        return command;
    }

    Result runHelper(String directory, Date cutoff, String skipArchiveOnFilesystemOf) {
        List<String> command = helperCommand(directory, cutoff, skipArchiveOnFilesystemOf);
        StringBuilder output = new StringBuilder();
        int exitCode;
        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(true);
            Process process = builder.start();
            process.getOutputStream().close();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append('\n');
                }
            }
            if (!process.waitFor(HELPER_TIMEOUT_MINUTES, TimeUnit.MINUTES)) {
                process.destroyForcibly();
                return new Result(false, 0, "", null, "helper timed out"); //$NON-NLS-1$ //$NON-NLS-2$
            }
            exitCode = process.exitValue();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return new Result(false, 0, "", null, "interrupted"); //$NON-NLS-1$ //$NON-NLS-2$
        } catch (Exception exception) {
            return new Result(false, 0, "", null, exception.toString()); //$NON-NLS-1$
        }
        return parseHelperOutput(exitCode, output.toString());
    }

    static Result parseHelperOutput(int exitCode, String output) {
        String text = output == null ? "" : output.trim(); //$NON-NLS-1$
        if (exitCode != 0 || !text.startsWith("SUCCESS")) { //$NON-NLS-1$
            return new Result(false, 0, "", null, //$NON-NLS-1$
                    text.isEmpty() ? "exit code " + exitCode : text.replace('\n', ' ')); //$NON-NLS-1$
        }
        long deleted = 0;
        String archive = ""; //$NON-NLS-1$
        String vacuumFailure = null;
        String archiveSkipped = null;
        for (String line : text.split("\n")) { //$NON-NLS-1$
            if (line.startsWith("DELETED: ")) { //$NON-NLS-1$
                deleted = Long.parseLong(line.substring("DELETED: ".length()).trim()); //$NON-NLS-1$
            } else if (line.startsWith("ARCHIVE: ")) { //$NON-NLS-1$
                archive = line.substring("ARCHIVE: ".length()).trim(); //$NON-NLS-1$
            } else if (line.startsWith("VACUUM_FAILED: ")) { //$NON-NLS-1$
                vacuumFailure = line.substring("VACUUM_FAILED: ".length()).trim(); //$NON-NLS-1$
            } else if (line.startsWith("ARCHIVE_SKIPPED: ")) { //$NON-NLS-1$
                archiveSkipped = line.substring("ARCHIVE_SKIPPED: ".length()).trim(); //$NON-NLS-1$
            }
        }
        return new Result(true, deleted, archive, vacuumFailure, null, archiveSkipped);
    }

    private void report(AuditLogable event, AuditLogType type) {
        try {
            auditLogDirector.log(event, type);
        } catch (RuntimeException exception) {
            log.error("Unable to record audit log purge event {}", type, exception);
        }
    }

    static boolean isCapacityPurgeEnabled() {
        try {
            Boolean enabled = Config.<Boolean> getValue(ConfigValues.ENGINE_AUDIT_CAPACITY_PURGE_ENABLED);
            return enabled == null || enabled;
        } catch (RuntimeException exception) {
            return true;
        }
    }

    private static String archiveDirectory() {
        try {
            String directory = Config.<String> getValue(ConfigValues.ENGINE_AUDIT_PURGE_ARCHIVE_DIR);
            return directory == null || directory.trim().isEmpty() ? DEFAULT_ARCHIVE_DIR : directory.trim();
        } catch (RuntimeException exception) {
            return DEFAULT_ARCHIVE_DIR;
        }
    }

    private static int configInt(ConfigValues key, int fallback) {
        try {
            Integer value = Config.<Integer> getValue(key);
            return value == null || value <= 0 ? fallback : value;
        } catch (RuntimeException exception) {
            return fallback;
        }
    }

    private static String formatTime(Date time) {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.ROOT); //$NON-NLS-1$
        format.setTimeZone(TimeZone.getDefault());
        return format.format(time);
    }
}
