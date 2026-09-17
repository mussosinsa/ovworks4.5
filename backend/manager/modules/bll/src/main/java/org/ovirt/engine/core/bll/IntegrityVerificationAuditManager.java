package org.ovirt.engine.core.bll;

import java.time.ZoneId;
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
 * Puts what the AIDE integrity verification found into the event list, on its own.
 *
 * <p>The integrity verification runs from the daily timer and from the WebAdmin screen, and until
 * now only the screen's run said anything in the event list - and only whether it succeeded. The
 * scheduled run, which is the one nobody is watching, reported nothing at all: it wrote to a log
 * file on the engine host and that was the whole account of it.</p>
 *
 * <p>It is reported apart from the security audit, under its own event types, because the two
 * answer different questions. The security audit says whether the installation is configured
 * securely; this says whether its files are still the files that were installed. A record that
 * ran them together would let one of them pass for the other.</p>
 */
@Singleton
public class IntegrityVerificationAuditManager implements BackendService {

    private static final Logger log = LoggerFactory.getLogger(IntegrityVerificationAuditManager.class);

    /** Names this verification's row in the ledger of what has been reported. */
    static final String KIND = "integrity"; //$NON-NLS-1$

    /** A run from the WebAdmin screen reports itself, see IntegrityVerificationCommand. */
    private static final String WEBADMIN = "webadmin"; //$NON-NLS-1$

    /** How long after startup the first look is taken, leaving the engine to finish coming up. */
    private static final long START_DELAY_SECONDS = 45;

    /** How often a new result is looked for. The timer that produces them runs once a day. */
    private static final long CHECK_INTERVAL_SECONDS = 300;

    /**
     * How many files are reported one by one.
     *
     * <p>A baseline taken before a package update reports every file the update touched, and all
     * of those in the event list would bury everything else in it. The rest are counted in one
     * closing record and stay in the AIDE report, which is not being emptied.</p>
     */
    private static final int MAX_REPORTED_CHANGES = 50;

    @Inject
    @ThreadPools(ThreadPools.ThreadPoolType.EngineScheduledThreadPool)
    private ManagedScheduledExecutorService executor;

    @Inject
    private AuditLogDao auditLogDao;

    @PostConstruct
    private void init() {
        log.info("Start initializing {}", getClass().getSimpleName());
        executor.scheduleWithFixedDelay(this::reportNewResult,
                START_DELAY_SECONDS,
                CHECK_INTERVAL_SECONDS,
                TimeUnit.SECONDS);
        log.info("Finished initializing {}", getClass().getSimpleName());
    }

    void reportNewResult() {
        try {
            Optional<IntegrityVerification.Result> result = IntegrityVerification.readResult();
            if (result.isEmpty()) {
                return;
            }
            IntegrityVerification.Result integrity = result.get();
            if (WEBADMIN.equals(integrity.getSource())) {
                // Already in the event list: the command that ran it recorded it as it went,
                // with the account that asked for it.
                return;
            }
            if (VerificationReportLedger.alreadyReported(KIND, integrity.getTimestamp())) {
                return;
            }
            report(integrity);
            VerificationReportLedger.markReported(KIND, integrity.getTimestamp());
        } catch (Throwable t) {
            // The next pass reads the same file; a pass that failed loses nothing and must not
            // take the scheduled task down with it.
            log.error("Exception in reporting the integrity verification: {}",
                    ExceptionUtils.getRootCauseMessage(t));
            log.debug("Exception", t);
        }
    }

    private void report(IntegrityVerification.Result result) {
        String when = StartupSecurityAuditManager.at(result.getTimestamp(), ZoneId.systemDefault());
        String ran = ranBy(result.getSource());

        logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_STARTED,
                "Integrity verification ran" + ran + when);

        if (result.isError()) {
            // Not the same answer as finding nothing: nothing was checked. Said as its own
            // outcome, because an event list with no finding in it is what a host that was
            // never checked and a host that is intact both look like.
            log.warn("무결성 검사를 수행하지 못함; status='{}'; exitCode={}",
                    result.getStatus(), result.getExitCode());
            logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_FAILED,
                    "Integrity verification could not be carried out" + ran + when
                            + "; AIDE exit code " + result.getExitCode()
                            + reportedIn(result));
            return;
        }

        int reported = reportChanges(result);

        if (result.isPassed()) {
            log.info("무결성 검사 결과 정상{}", ran);
            logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_COMPLETED,
                    "Integrity verification completed" + ran + when
                            + ": no file differs from the integrity database");
        } else {
            log.warn("무결성 검사에서 변경이 확인됨; 파일 수={}", reported);
            logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_FAILED,
                    "Integrity verification reported files that no longer match the integrity "
                            + "database" + ran + when + ": " + reported + " file(s)"
                            + reportedIn(result));
        }
    }

    /**
     * Puts each file AIDE named into the event list on a line of its own.
     *
     * <p>The closing record says how many; without these it would not say which, and the answer
     * would be in a report on the engine host that nobody reading the event list is looking at.
     * A file that has gone missing is recorded apart from one that was added or altered.</p>
     *
     * @return how many files AIDE named in all, not how many were recorded one by one
     */
    private int reportChanges(IntegrityVerification.Result result) {
        List<IntegrityVerification.Change> changes =
                IntegrityVerification.changesInLog(result.getLogFile());
        int recorded = Math.min(changes.size(), MAX_REPORTED_CHANGES);
        for (IntegrityVerification.Change change : changes.subList(0, recorded)) {
            boolean missing = change.getKind() == IntegrityVerification.Change.Kind.REMOVED;
            logAuditEvent(missing
                    ? AuditLogType.INTEGRITY_VERIFICATION_FILE_MISSING
                    : AuditLogType.INTEGRITY_VERIFICATION_FILE_MODIFIED,
                    change.describe());
        }
        if (changes.size() > recorded) {
            logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_WARNING,
                    "Integrity verification reported " + (changes.size() - recorded)
                            + " further file(s)" + reportedIn(result));
        }
        return changes.size();
    }

    /** Names what asked for the verification, so a scheduled run is not read as somebody's. */
    private static String ranBy(String source) {
        return source == null || source.isEmpty()
                ? "" //$NON-NLS-1$
                : " (" + source + ")"; //$NON-NLS-1$ //$NON-NLS-2$
    }

    /** Names the report, so that what was left out of the event list can still be read. */
    private static String reportedIn(IntegrityVerification.Result result) {
        return result.getLogFile() == null
                ? "" //$NON-NLS-1$
                : "; see " + result.getLogFile(); //$NON-NLS-1$
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
