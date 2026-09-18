package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.enterprise.concurrent.ManagedScheduledExecutorService;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.BackendService;
import org.ovirt.engine.core.common.businessentities.AuditLog;
import org.ovirt.engine.core.dao.AuditLogDao;
import org.ovirt.engine.core.utils.threadpool.ThreadPools;
import org.ovirt.engine.core.utils.transaction.TransactionSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Puts what the configuration-file cryptography did into the event list.
 *
 * <p>Almost none of it happens while there is an engine to record it. The database
 * configuration is decrypted before the Java daemon is launched, and the keys are created by
 * engine-setup, so a failure in either had no engine to write an event and the only sign of it
 * was that the engine did not start. The tools leave each result in a spool instead, and this
 * records them at the next start that succeeds, and as they appear after that.</p>
 *
 * <p>An entry is removed once it is recorded, so it is recorded once. One that cannot be read
 * is moved aside rather than deleted: it is somebody's account of a cryptographic operation,
 * and throwing it away would be the one outcome nobody could look into afterwards.</p>
 */
@Singleton
public class CryptoEventAuditManager implements BackendService {

    private static final Logger log = LoggerFactory.getLogger(CryptoEventAuditManager.class);

    /** Where the tools leave them, see ovirt_engine.cryptoevents. */
    static final String SPOOL_DIR = "/var/lib/ovirt-engine/security/crypto-events"; //$NON-NLS-1$

    /** Where an entry goes when it cannot be read. */
    static final String REJECTED_DIR = SPOOL_DIR + "/rejected"; //$NON-NLS-1$

    /** A moment for the engine to finish coming up before rows are written on its behalf. */
    private static final long START_DELAY_SECONDS = 40;

    /** How often the spool is looked at afterwards. Setup and starts are what fill it. */
    private static final long CHECK_INTERVAL_SECONDS = 120;

    /**
     * How many entries one pass records.
     *
     * <p>A spool that has grown without bound - nothing drained it for a month of daily
     * encryption - would otherwise be one transaction per entry with nothing else getting a
     * turn. What is left waits for the next pass, which is two minutes away.</p>
     */
    private static final int MAX_PER_PASS = 100;

    @Inject
    @ThreadPools(ThreadPools.ThreadPoolType.EngineScheduledThreadPool)
    private ManagedScheduledExecutorService executor;

    @Inject
    private AuditLogDao auditLogDao;

    /** Set once the spool has been reported unreadable, so it is said once and not every pass. */
    private boolean reportedUnreadable;

    @PostConstruct
    private void init() {
        log.info("Start initializing {}", getClass().getSimpleName());
        executor.scheduleWithFixedDelay(this::drainSpool,
                START_DELAY_SECONDS,
                CHECK_INTERVAL_SECONDS,
                TimeUnit.SECONDS);
        log.info("Finished initializing {}", getClass().getSimpleName());
    }

    void drainSpool() {
        try {
            Path spool = Paths.get(SPOOL_DIR);
            if (!Files.isDirectory(spool)) {
                // Nothing has written one. Not a fault: an installation whose configuration is
                // not encrypted never runs any of this.
                return;
            }
            if (!Files.isReadable(spool)) {
                reportUnreadable(spool);
                return;
            }
            reportedUnreadable = false;
            for (Path entry : entries(spool)) {
                record(entry);
            }
        } catch (Throwable t) {
            // The next pass reads the same directory; a pass that failed loses nothing and must
            // not take the scheduled task down with it.
            log.error("Exception in reporting cryptography events: {}",
                    ExceptionUtils.getRootCauseMessage(t));
            log.debug("Exception", t);
        }
    }

    /**
     * The entries waiting, oldest first.
     *
     * <p>In the order they were written, so that the event list reads in the order things
     * happened rather than in whatever order the directory hands them over. Only the finished
     * ones: the writer builds each entry under a dotted name and renames it, so a name that
     * starts with a dot is one still being written.</p>
     */
    private List<Path> entries(Path spool) throws IOException {
        List<Path> entries = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(spool, "*.json")) { //$NON-NLS-1$
            for (Path entry : stream) {
                if (Files.isRegularFile(entry) && !entry.getFileName().toString().startsWith(".")) { //$NON-NLS-1$
                    entries.add(entry);
                }
            }
        }
        entries.sort(Comparator.comparing(CryptoEventAuditManager::writtenAt));
        return entries.size() > MAX_PER_PASS ? entries.subList(0, MAX_PER_PASS) : entries;
    }

    private static long writtenAt(Path entry) {
        try {
            return Files.getLastModifiedTime(entry).toMillis();
        } catch (IOException e) {
            return 0;
        }
    }

    private void record(Path entry) {
        Optional<CryptoEvent> event = CryptoEvent.parse(entry);
        if (event.isEmpty()) {
            reject(entry);
            return;
        }
        CryptoEvent crypto = event.get();
        log.info("암호연산 이벤트 기록; event='{}'; id='{}'",
                crypto.getAuditLogType().name(), crypto.getId());
        logAuditEvent(crypto.getAuditLogType(),
                crypto.describe(StartupSecurityAuditManager.at(
                        crypto.getTimestamp(), ZoneId.systemDefault())));
        remove(entry);
    }

    /**
     * Sets an entry aside that cannot be read, and says so.
     *
     * <p>Moved rather than deleted. It is an account of something cryptographic that happened
     * on this host, written by a tool that thought it was worth recording; whether it is
     * damaged, truncated or forged, deleting it is the one outcome that leaves nobody able to
     * find out which.</p>
     */
    private void reject(Path entry) {
        log.warn("암호연산 이벤트를 읽을 수 없어 격리함; path='{}'", entry);
        logAuditEvent(AuditLogType.CRYPTO_EVENT_SPOOL_REJECTED,
                "A cryptography event could not be read and was set aside in " + REJECTED_DIR); //$NON-NLS-1$
        try {
            Path rejected = Paths.get(REJECTED_DIR);
            Files.createDirectories(rejected);
            Files.move(entry, rejected.resolve(entry.getFileName()));
        } catch (IOException | RuntimeException e) {
            // Left where it is. It is read again at the next pass and rejected again, which is
            // noisy; it is not as bad as removing the one copy of it.
            log.error("Unable to set aside the cryptography event {}: {}", entry, e.getMessage()); //$NON-NLS-1$
        }
    }

    private void remove(Path entry) {
        try {
            Files.deleteIfExists(entry);
        } catch (IOException | RuntimeException e) {
            // Recorded again at the next pass otherwise, so it is worth saying loudly.
            log.error("Unable to remove the recorded cryptography event {}: {}", //$NON-NLS-1$
                    entry, e.getMessage());
        }
    }

    /**
     * Says, once, that the spool is there and cannot be read.
     *
     * <p>Unreadable means cryptographic results are not reaching the event list, and the event
     * list looks the same either way - empty, which is also what it looks like when nothing has
     * been encrypted or decrypted at all.</p>
     */
    private void reportUnreadable(Path spool) {
        if (reportedUnreadable) {
            return;
        }
        reportedUnreadable = true;
        log.warn("암호연산 이벤트 spool 을 읽을 수 없음; path='{}'", spool);
        logAuditEvent(AuditLogType.CRYPTO_EVENT_SPOOL_REJECTED,
                "Cryptography events are not being reported: " + SPOOL_DIR //$NON-NLS-1$
                        + " cannot be read by the engine"); //$NON-NLS-1$
    }

    private void logAuditEvent(AuditLogType type, String message) {
        AuditLog auditLog = new AuditLog(type, type.getSeverity());
        auditLog.setMessage(message);
        auditLog.setCustomData(message);
        TransactionSupport.executeInNewTransaction(() -> {
            auditLogDao.save(auditLog);
            return null;
        });
    }
}
