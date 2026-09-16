package org.ovirt.engine.core.bll;

import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
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
 * Puts the result of the security verification the service ran before starting into the event list.
 *
 * <p>The verification is not run here. {@code ovirt-engine.py} runs it as a gate before the Java
 * daemon is launched at all - a start whose verification fails does not happen - and what it found
 * went only to the systemd journal and to engine.log. Neither is where an administrator looks, and
 * the event list said nothing about the state the engine had just come up in.</p>
 *
 * <p>So the audit is read rather than repeated: running it a second time would spend minutes
 * checking what was checked a moment ago, and the two runs would contend for the lock the
 * verification script takes.</p>
 */
@Singleton
public class StartupSecurityAuditManager implements BackendService {

    private static final Logger log = LoggerFactory.getLogger(StartupSecurityAuditManager.class);

    /**
     * How long after startup the result is published.
     *
     * <p>The audit itself has already run, so this is only a pause for the engine to finish coming
     * up before rows are written on its behalf. Nothing waits on it either way.</p>
     */
    private static final long REPORT_DELAY_SECONDS = 30;

    /**
     * How many checks that did not pass are reported one by one.
     *
     * <p>Every one of them is worth seeing, and there are only ever as many as the audit has
     * checks. The cap is there so that an audit that goes wrong and reports on everything cannot
     * fill the event list; the tally in the closing record still counts them all.</p>
     */
    private static final int MAX_REPORTED_FINDINGS = 50;

    /** {@code 2026-09-17T06:51:40+09:00}, as the verification script's own log writes a time. */
    private static final DateTimeFormatter AUDIT_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX"); //$NON-NLS-1$

    @Inject
    @ThreadPools(ThreadPools.ThreadPoolType.EngineScheduledThreadPool)
    private ManagedScheduledExecutorService executor;

    @Inject
    private AuditLogDao auditLogDao;

    @PostConstruct
    private void init() {
        log.info("Start initializing {}", getClass().getSimpleName());
        executor.schedule(this::reportPreStartAudit, REPORT_DELAY_SECONDS, TimeUnit.SECONDS);
        log.info("Finished initializing {}", getClass().getSimpleName());
    }

    void reportPreStartAudit() {
        try {
            Optional<SecurityAuditRunner.Result> result = SecurityAuditRunner.readResult();
            if (result.isEmpty()) {
                log.warn("엔진 기동 보안검증 결과를 읽을 수 없음; path='{}'", SecurityAuditRunner.getResultsPath());
                logAuditEvent(AuditLogType.SECURITY_AUDIT_WARNING,
                        "Security audit result of the pre-start verification could not be read from "
                                + SecurityAuditRunner.getResultsPath());
                return;
            }
            report(result.get());
        } catch (Throwable t) {
            // The engine is already serving requests. A result that cannot be reported is said to
            // be so and must not take anything else down with it.
            log.error("Exception in reporting the pre-start security audit: {}",
                    ExceptionUtils.getRootCauseMessage(t));
            log.debug("Exception", t);
            logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED,
                    "Security audit result of the pre-start verification could not be reported: "
                            + ExceptionUtils.getRootCauseMessage(t));
        }
    }

    private void report(SecurityAuditRunner.Result result) {
        logAuditEvent(AuditLogType.SECURITY_AUDIT_STARTED,
                "Security audit ran before the engine started" + at(result));

        reportFindings(result.getLogFile());

        String detail = at(result) + ": " + result.getSummary();
        if (result.isPassed()) {
            log.info("엔진 기동 보안검증 결과 정상; {}", result.getSummary());
            logAuditEvent(AuditLogType.SECURITY_AUDIT_COMPLETED,
                    "Security audit completed before the engine started" + detail);
        } else {
            log.warn("엔진 기동 보안검증 결과 점검 필요; {}", result.getSummary());
            logAuditEvent(AuditLogType.SECURITY_AUDIT_WARNING,
                    "Security audit reported failed checks before the engine started" + detail);
        }
    }

    /**
     * Puts each check that did not pass into the event list on a line of its own.
     *
     * <p>The closing record says how many there were; without these it would not say which, and
     * the answer would be in a log file on the engine host that nobody reading the event list is
     * looking at.</p>
     */
    private void reportFindings(Path auditLog) {
        List<SecurityAuditRunner.Finding> findings = SecurityAuditRunner.findingsInLog(auditLog);
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
                            + " further checks that did not pass; see " + auditLog);
        }
    }

    /** When the audit ran, so that a record cannot be mistaken for one left by an earlier start. */
    private static String at(SecurityAuditRunner.Result result) {
        return at(result.getTimestamp(), ZoneId.systemDefault());
    }

    /**
     * Writes the time the audit ran the way the rest of the engine writes times.
     *
     * <p>The audit script records it in UTC. Printing it back as UTC put a time in the message
     * that did not match the time beside it in the event list - which is the reader's own - and
     * an event that says 06:52 carrying a message that says 21:51 reads as two different events.
     * So it is written in the engine host's own time, with the offset spelled out, the way the
     * verification script's own log writes it.</p>
     */
    static String at(Instant timestamp, ZoneId zone) {
        return timestamp == null ? "" : " at " + AUDIT_TIME.format(timestamp.atZone(zone));
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
