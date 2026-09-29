package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import javax.annotation.PostConstruct;
import javax.enterprise.concurrent.ManagedScheduledExecutorService;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.BackendService;
import org.ovirt.engine.core.common.businessentities.AuditLogCapacityStatus;
import org.ovirt.engine.core.common.config.Config;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogableImpl;
import org.ovirt.engine.core.utils.threadpool.ThreadPools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class AuditLogCapacityMonitor implements BackendService {

    static final int WARNING_REMAINING_PERCENT = 5;
    private static final Logger log = LoggerFactory.getLogger(AuditLogCapacityMonitor.class);
    private static final long BYTES_PER_MIB = 1024L * 1024L;

    @Inject
    private AuditLogDirector auditLogDirector;

    @Inject
    @ThreadPools(ThreadPools.ThreadPoolType.EngineScheduledThreadPool)
    private ManagedScheduledExecutorService executor;

    private final AtomicBoolean warningActive = new AtomicBoolean();
    private final AtomicBoolean exceededActive = new AtomicBoolean();

    /**
     * The last reading, for a screen to show.
     *
     * <p>The monitor measured this every minute and said nothing about it unless it was running
     * short, so how full the storage was could not be looked at - only waited for. Kept here so
     * that a screen reads what the monitor already measured rather than walking the directory
     * again on every refresh.</p>
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
        if (!configure()) {
            return;
        }
        Path auditLogDirectory = monitoredDirectory;
        long limit = maxBytes;
        notifyMonitorStarted(auditLogDirectory, limit / BYTES_PER_MIB, checkIntervalSeconds);
        executor.scheduleWithFixedDelay(
                () -> checkCapacity(auditLogDirectory, limit),
                0,
                checkIntervalSeconds,
                TimeUnit.SECONDS);
    }

    /**
     * Reads what is to be watched, and how often.
     *
     * <p>Apart from the scheduling so that the configuration is also kept where a screen can read
     * it: what the limit is, and where the records are, are half of what such a screen shows, and
     * they were previously local variables inside the scheduling.</p>
     *
     * @return whether there is anything to watch - false when monitoring is switched off by
     *         configuration, and when the configuration cannot be read at all
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
            if (maxSizeMiB <= 0 || interval <= 0) {
                log.info("Audit log capacity monitoring is disabled");
                return false;
            }
            maxBytes = Math.multiplyExact(maxSizeMiB, BYTES_PER_MIB);
            return true;
        } catch (RuntimeException exception) {
            log.error("Audit log capacity monitoring configuration is invalid; monitoring is disabled", exception);
            return false;
        }
    }

    void checkCapacity(Path directory, long maxBytes) {
        try {
            long usedBytes = calculateDirectorySize(directory);
            boolean exceeded = usedBytes >= maxBytes;
            boolean warning = isWithinWarningRange(usedBytes, maxBytes, WARNING_REMAINING_PERCENT);

            // Kept before anything is decided about it, so that a screen shows what was measured
            // whether or not this pass had something to report.
            lastReading = new Reading(usedBytes, Instant.now(), null);

            if (exceeded) {
                warningActive.set(false);
                if (exceededActive.compareAndSet(false, true)) {
                    notifyAdministrator(AuditLogType.AUDIT_LOG_CAPACITY_EXCEEDED, usedBytes, maxBytes);
                }
            } else if (warning) {
                exceededActive.set(false);
                if (warningActive.compareAndSet(false, true)) {
                    notifyAdministrator(AuditLogType.AUDIT_LOG_CAPACITY_WARNING, usedBytes, maxBytes);
                }
            } else {
                boolean recovered = warningActive.getAndSet(false) | exceededActive.getAndSet(false);
                if (recovered) {
                    notifyAdministrator(AuditLogType.AUDIT_LOG_CAPACITY_RECOVERED, usedBytes, maxBytes);
                }
            }
        } catch (IOException | RuntimeException exception) {
            // Remembered as a reading that could not be taken. Leaving the previous one standing
            // would have the screen showing a figure from before the directory became unreadable,
            // with nothing to say that it is no longer being measured.
            lastReading = new Reading(0, Instant.now(), describe(exception));
            log.error("Unable to measure audit log capacity in {}", directory, exception);
        }
    }

    /**
     * The last reading, as a screen shows it.
     *
     * <p>Measured here rather than read from the database: what fills up is a directory on the
     * engine host, and nothing about its size is in the database to be queried. A screen therefore
     * has to ask the process that is already measuring it.</p>
     *
     * <p>Answers even when the monitor is not running, because "not being measured" is the state an
     * administrator most needs to be told about and the one that otherwise shows as an empty
     * screen. When there is no reading yet - the engine has just started, or the first pass has not
     * finished - one is taken here so that the screen is not blank for the first minute.</p>
     */
    public AuditLogCapacityStatus getStatus() {
        AuditLogCapacityStatus status = new AuditLogCapacityStatus();
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

    /** One measurement, or one attempt at it. */
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

    private void notifyAdministrator(AuditLogType type, long usedBytes, long maxBytes) {
        AuditLogable event = new AuditLogableImpl();
        event.addCustomValue("UsedSizeMiB", Long.toString(usedBytes / BYTES_PER_MIB)); //$NON-NLS-1$
        event.addCustomValue("MaxSizeMiB", Long.toString(maxBytes / BYTES_PER_MIB)); //$NON-NLS-1$
        event.addCustomValue("RemainingPercent", Long.toString(remainingPercent(usedBytes, maxBytes))); //$NON-NLS-1$
        auditLogDirector.log(event, type);
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
}
