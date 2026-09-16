package org.ovirt.engine.core.bll;

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
 * Audits the installation once the engine has started, and records the result in the audit log.
 *
 * <p>The audit could be run from the WebAdmin screen and nowhere else, so whether an installation
 * was ever checked depended on somebody remembering to check it, and the audit log said nothing
 * about the state the engine came up in. Running it at startup puts a dated result in the audit
 * log for every start of the service.</p>
 */
@Singleton
public class StartupSecurityAuditManager implements BackendService {

    private static final Logger log = LoggerFactory.getLogger(StartupSecurityAuditManager.class);

    /**
     * How long after startup the audit begins.
     *
     * <p>The audit reads configuration, files and the database, so it waits for the engine to
     * finish coming up rather than competing with it. Nothing waits on the audit: it runs on the
     * scheduled pool and the engine is serving requests throughout.</p>
     */
    private static final long START_DELAY_MINUTES = 2;

    /** What the runner script records as having asked for the audit. */
    private static final String SOURCE = "startup"; //$NON-NLS-1$

    /**
     * How many checks that did not pass are reported one by one.
     *
     * <p>Every one of them is worth seeing, and there are only ever as many as the audit has
     * checks. The cap is there so that an audit that goes wrong and reports on everything cannot
     * fill the event list; the tally in the closing record still counts them all.</p>
     */
    private static final int MAX_REPORTED_FINDINGS = 50;

    @Inject
    @ThreadPools(ThreadPools.ThreadPoolType.EngineScheduledThreadPool)
    private ManagedScheduledExecutorService executor;

    @Inject
    private AuditLogDao auditLogDao;

    @PostConstruct
    private void init() {
        log.info("Start initializing {}", getClass().getSimpleName());
        executor.schedule(this::auditOnStartup, START_DELAY_MINUTES, TimeUnit.MINUTES);
        log.info("Finished initializing {}", getClass().getSimpleName());
    }

    void auditOnStartup() {
        try {
            if (!SecurityAuditRunner.isAvailable()) {
                log.warn("엔진 기동 보안검증 생략; 실행기를 사용할 수 없음: {}", SecurityAuditRunner.RUNNER);
                logAuditEvent(AuditLogType.SECURITY_AUDIT_WARNING,
                        "Security audit skipped at engine startup: the verification runner is unavailable at "
                                + SecurityAuditRunner.RUNNER);
                return;
            }

            log.info("엔진 기동 보안검증 실행 시작; runner='{}'", SecurityAuditRunner.RUNNER);
            logAuditEvent(AuditLogType.SECURITY_AUDIT_STARTED, "Security audit started at engine startup");

            SecurityAuditRunner.Run run = SecurityAuditRunner.run("security", SOURCE); //$NON-NLS-1$
            for (String line : run.getOutput().split("\n")) { //$NON-NLS-1$
                log.info("Security Audit: {}", line);
            }
            reportFindings(run);
            report(run);
        } catch (Throwable t) {
            // The engine is already serving requests; an audit that cannot be run is reported and
            // must not take anything else down with it.
            log.error("Exception in the security audit at engine startup: {}",
                    ExceptionUtils.getRootCauseMessage(t));
            log.debug("Exception", t);
            logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED,
                    "Security audit failed at engine startup: " + ExceptionUtils.getRootCauseMessage(t));
        }
    }

    /**
     * Puts each check that did not pass into the event list on a line of its own.
     *
     * <p>The closing record says how many there were; without these it would not say which, and
     * the answer would be in a log file on the engine host that nobody reading the event list is
     * looking at.</p>
     */
    private void reportFindings(SecurityAuditRunner.Run run) {
        List<SecurityAuditRunner.Finding> findings = SecurityAuditRunner.findingsIn(run.getOutput());
        int reported = Math.min(findings.size(), MAX_REPORTED_FINDINGS);
        for (SecurityAuditRunner.Finding finding : findings.subList(0, reported)) {
            boolean failed = finding.getLevel() == SecurityAuditRunner.Finding.Level.FAILED;
            logAuditEvent(
                    failed ? AuditLogType.SECURITY_AUDIT_FAILED : AuditLogType.SECURITY_AUDIT_WARNING,
                    (failed ? "Security audit check failed: " : "Security audit check warning: ")
                            + finding.getText());
        }
        if (findings.size() > reported) {
            logAuditEvent(AuditLogType.SECURITY_AUDIT_WARNING,
                    "Security audit reported " + (findings.size() - reported)
                            + " further checks that did not pass; see the audit log on the engine host");
        }
    }

    private void report(SecurityAuditRunner.Run run) {
        String counts = summaryText();
        switch (run.getOutcome()) {
            case PASSED:
                log.info("엔진 기동 보안검증 결과 정상; {}", counts);
                logAuditEvent(AuditLogType.SECURITY_AUDIT_COMPLETED,
                        "Security audit completed at engine startup: " + counts);
                break;
            case FINDINGS:
                log.warn("엔진 기동 보안검증 결과 점검 필요; {}", counts);
                logAuditEvent(AuditLogType.SECURITY_AUDIT_WARNING,
                        "Security audit completed at engine startup and reported failed checks: " + counts);
                break;
            case BUSY:
                log.info("엔진 기동 보안검증 생략; 다른 검증이 이미 실행 중");
                logAuditEvent(AuditLogType.SECURITY_AUDIT_WARNING,
                        "Security audit skipped at engine startup: another verification was already running");
                break;
            case TIMED_OUT:
                log.error("엔진 기동 보안검증 시간 초과; timeoutMinutes={}", SecurityAuditRunner.TIMEOUT_MINUTES);
                logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED,
                        "Security audit timed out at engine startup after " + SecurityAuditRunner.TIMEOUT_MINUTES
                                + " minutes");
                break;
            default:
                log.error("엔진 기동 보안검증 실패; exitCode={}", run.getExitCode());
                logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED,
                        "Security audit failed at engine startup with exit code " + run.getExitCode());
        }
    }

    /**
     * The tally to put in the audit record, so that the record says what was checked rather than
     * only that something was.
     */
    private String summaryText() {
        Optional<SecurityAuditRunner.Summary> summary = SecurityAuditRunner.readSummary();
        return summary.map(SecurityAuditRunner.Summary::toString)
                .orElse("the audit left no result to read"); //$NON-NLS-1$
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
