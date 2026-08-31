package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import javax.annotation.PostConstruct;
import javax.enterprise.concurrent.ManagedScheduledExecutorService;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.BackendService;
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

    @PostConstruct
    private void initialize() {
        try {
            long maxSizeMiB = Config.<Long> getValue(ConfigValues.ENGINE_AUDIT_LOG_MAX_SIZE_MB);
            long checkIntervalSeconds =
                    Config.<Long> getValue(ConfigValues.ENGINE_AUDIT_LOG_CAPACITY_CHECK_INTERVAL_SECONDS);
            if (maxSizeMiB <= 0 || checkIntervalSeconds <= 0) {
                log.info("Audit log capacity monitoring is disabled");
                return;
            }

            Path auditLogDirectory = Paths.get(Config.<String> getValue(ConfigValues.ENGINE_AUDIT_LOG_DIR));
            long maxBytes = Math.multiplyExact(maxSizeMiB, BYTES_PER_MIB);
            notifyMonitorStarted(auditLogDirectory, maxSizeMiB, checkIntervalSeconds);
            executor.scheduleWithFixedDelay(
                    () -> checkCapacity(auditLogDirectory, maxBytes),
                    0,
                    checkIntervalSeconds,
                    TimeUnit.SECONDS);
        } catch (RuntimeException exception) {
            log.error("Audit log capacity monitoring configuration is invalid; monitoring is disabled", exception);
        }
    }

    void checkCapacity(Path directory, long maxBytes) {
        try {
            long usedBytes = calculateDirectorySize(directory);
            boolean exceeded = usedBytes >= maxBytes;
            boolean warning = isWithinWarningRange(usedBytes, maxBytes, WARNING_REMAINING_PERCENT);

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
            log.error("Unable to measure audit log capacity in {}", directory, exception);
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
