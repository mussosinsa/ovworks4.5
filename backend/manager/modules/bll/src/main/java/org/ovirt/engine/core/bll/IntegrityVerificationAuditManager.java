package org.ovirt.engine.core.bll;

import java.time.Duration;
import java.time.Instant;
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
 *
 * <p>A verification is also run once after the engine starts, so that a host is not taken to be
 * intact for a whole day on the strength of a check made before whatever was done to it. It is
 * run from here rather than from the start gate: AIDE walks the filesystem and takes minutes,
 * and a gate that took minutes would run into systemd's start timeout and stop the engine from
 * starting at all. So the engine comes up first and the verification follows it.</p>
 */
@Singleton
public class IntegrityVerificationAuditManager implements BackendService {

    private static final Logger log = LoggerFactory.getLogger(IntegrityVerificationAuditManager.class);

    /** Names this verification's row in the ledger of what has been reported. */
    static final String KIND = "integrity"; //$NON-NLS-1$

    /** A run from the WebAdmin screen reports itself, see IntegrityVerificationCommand. */
    private static final String WEBADMIN = "webadmin"; //$NON-NLS-1$

    /** What the verification run after the engine starts names itself. */
    static final String ENGINE_START = "engine-start"; //$NON-NLS-1$

    /** Which checks the runner script is asked for. */
    private static final String INTEGRITY_MODE = "integrity"; //$NON-NLS-1$

    /**
     * Names whether a verification is run after the engine starts.
     *
     * <p>{@code false} never runs one, {@code always} runs one at every start, and anything else
     * - including the variable being unset - runs one only when the last verification is older
     * than {@link #MAX_AGE}.</p>
     */
    private static final String ON_START_ENV = "INTEGRITY_VERIFICATION_ON_START"; //$NON-NLS-1$

    /**
     * How old the last verification may be before a start runs another.
     *
     * <p>AIDE walks the whole filesystem, so a start that always ran one would make every
     * restart cost minutes of disk - and restarts come in threes when somebody is working on
     * the host. Shorter than the day between scheduled runs, so that a start still catches what
     * was done since the last one.</p>
     */
    private static final Duration MAX_AGE = Duration.ofHours(12);

    /** How long after startup the verification is run, leaving the engine to finish coming up. */
    private static final long VERIFY_DELAY_SECONDS = 120;

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
        // Scheduled, not run here: @PostConstruct runs while the engine is still coming up, and
        // AIDE takes minutes. Nothing waits on it either way.
        executor.schedule(this::verifyOnStart, VERIFY_DELAY_SECONDS, TimeUnit.SECONDS);
        log.info("Finished initializing {}", getClass().getSimpleName());
    }

    /**
     * Runs a verification once, after the engine has started.
     *
     * <p>Takes minutes and holds one thread of a pool of a hundred long-running ones for them.
     * Nothing waits on the result: it goes to the event list when it is ready.</p>
     */
    void verifyOnStart() {
        try {
            if (!shouldVerifyOnStart(System.getenv(ON_START_ENV), lastRun(), Instant.now())) {
                return;
            }
            if (!SecurityAuditRunner.isAvailable()) {
                log.warn("기동 후 무결성 검사를 실행할 수 없음; runner='{}'", SecurityAuditRunner.RUNNER);
                logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_FAILED,
                        "Integrity verification could not be run after the engine started: "
                                + SecurityAuditRunner.RUNNER);
                return;
            }
            log.info("기동 후 무결성 검사 실행 시작");
            SecurityAuditRunner.Run run = SecurityAuditRunner.run(INTEGRITY_MODE, ENGINE_START);
            if (run.getOutcome() == SecurityAuditRunner.Outcome.BUSY) {
                // Another verification holds the lock - the daily one, or one somebody started
                // from the screen. Nothing is lost: its own result is reported by the pass that
                // watches the result file, and it is checking the same files this would have.
                log.info("다른 검증이 실행 중이어서 기동 후 무결성 검사를 건너뜀");
                return;
            }
            if (run.getOutcome() == SecurityAuditRunner.Outcome.TIMED_OUT) {
                // The script did not finish, so it left no result for the pass below to find,
                // and silence here would read as a host that verified clean.
                log.warn("기동 후 무결성 검사가 시간 내에 끝나지 않음");
                logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_FAILED,
                        "Integrity verification started after the engine started did not finish "
                                + "within " + SecurityAuditRunner.TIMEOUT_MINUTES + " minutes");
                return;
            }
            // Reported now rather than at the next pass, which is minutes away.
            reportNewResult();
        } catch (Throwable t) {
            log.error("Exception in running the integrity verification after startup: {}",
                    ExceptionUtils.getRootCauseMessage(t));
            log.debug("Exception", t);
        }
    }

    /**
     * @param configured what {@link #ON_START_ENV} was set to, or null
     * @param lastRun when the last verification ran, or null when none has
     * @param now the time to measure that against
     * @return whether this start runs one
     */
    static boolean shouldVerifyOnStart(String configured, Instant lastRun, Instant now) {
        if ("false".equalsIgnoreCase(configured)) { //$NON-NLS-1$
            return false;
        }
        if ("always".equalsIgnoreCase(configured)) { //$NON-NLS-1$
            return true;
        }
        // A host that has never been verified is verified, whatever the age would have said:
        // no result at all is the case this is most worth running for.
        return lastRun == null || lastRun.isBefore(now.minus(MAX_AGE));
    }

    private static Instant lastRun() {
        return IntegrityVerification.readResult()
                .map(IntegrityVerification.Result::getTimestamp)
                .orElse(null);
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
    static String ranBy(String source) {
        if (ENGINE_START.equals(source)) {
            return " after the engine started"; //$NON-NLS-1$
        }
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
