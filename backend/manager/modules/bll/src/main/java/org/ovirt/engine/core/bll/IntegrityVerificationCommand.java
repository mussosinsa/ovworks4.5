package org.ovirt.engine.core.bll;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.ActionParametersBase;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.common.businessentities.AuditLog;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.AuditLogDao;
import org.ovirt.engine.core.utils.transaction.TransactionSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Command to verify integrity using AIDE.
 */
public class IntegrityVerificationCommand<T extends ActionParametersBase> extends CommandBase<T> {

    private static final Logger log = LoggerFactory.getLogger(IntegrityVerificationCommand.class);
    private static final String SECURITY_VERIFICATION_RUNNER =
            "/usr/share/ovirt-engine/bin/ovirt-engine-security-verification-runner.sh"; //$NON-NLS-1$

    /**
     * As many records as the scheduled run makes one by one, so the two read the same: every file
     * of every process, and an upgrade's changes under engine.ear up to the cap.
     */
    static final int MAX_REPORTED_FILES = 300;

    /** The runner's exit code for a verification that found files no longer matching. */
    static final int FOUND_CHANGES = 20;

    @Inject
    private AuditLogDao auditLogDao;

    @Inject
    private ScheduledVerificationFailureResponse failureResponse;

    public IntegrityVerificationCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected boolean validate() {
        return true;
    }

    @Override
    protected void executeCommand() {
        String userName = getCurrentUser().getLoginName();
        log.info("Integrity verification requested by user '{}'; runner='{}'", userName, SECURITY_VERIFICATION_RUNNER);
        logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_STARTED, "Integrity verification started");
        log.info("무결성 검사 실행 시작; user='{}'", userName);
        log.info("Integrity verification started by user '{}'", userName);

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(
                    SECURITY_VERIFICATION_RUNNER, "integrity", "webadmin"); //$NON-NLS-1$ //$NON-NLS-2$
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n"); //$NON-NLS-1$
                    log.info("Integrity verification: {}", line);
                }
            }

            int exitCode = process.waitFor();
            if (exitCode == 0) {
                reportChanges();
                log.info("무결성 검사 실행 결과 정상; user='{}'", userName);
                log.info("Integrity verification result: success; user='{}'; exitCode={}", userName, exitCode);
                logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_COMPLETED,
                        "Integrity verification completed: no file differs from the integrity database");
                setSucceeded(true);
            } else {
                String errorMsg = "무결성 검사 실패 (종료 코드: " + exitCode + ")";
                log.error("무결성 검사 실행 실패; user='{}'; exitCode={}", userName, exitCode);
                log.error("Integrity verification result: failure; user='{}'; exitCode={}", userName, exitCode);
                int changed = reportChanges();
                logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_FAILED,
                        changed > 0
                                ? "Integrity verification reported files that no longer match the "
                                        + "integrity database: " + changed + " file(s)"
                                : "Integrity verification failed with exit code: " + exitCode);
                logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_FAILURE_DETAIL, summary(exitCode));
                getReturnValue().getExecuteFailedMessages().add(errorMsg);
                setSucceeded(false);
                // As the timer's run: after the failure is recorded, the alert and - unless the
                // policy is NOTIFY - the engine stop after the configured delay. Only for files
                // found no longer matching (the runner's 20): a check that could not be carried
                // out (40), or did not start because another was running (75), found nothing,
                // and is alerted without stopping an engine that may be perfectly intact.
                boolean found = exitCode == FOUND_CHANGES || changed > 0;
                String halt = found
                        ? failureResponse.respond(IntegrityVerificationAuditManager.KIND,
                                ScheduledVerificationFailureResponse.WEBADMIN, Instant.now(),
                                changed + " file(s) no longer match the integrity database",
                                userName)
                        : failureResponse.recordUnverifiable(IntegrityVerificationAuditManager.KIND,
                                ScheduledVerificationFailureResponse.WEBADMIN, Instant.now(),
                                "exit code " + exitCode, userName);
                if (halt != null) {
                    getReturnValue().getExecuteFailedMessages().add(halt);
                }
            }

            getReturnValue().setActionReturnValue(output.toString());
        } catch (Exception e) {
            String errorMsg = "무결성 검사 실행 중 오류 발생: " + e.getMessage();
            log.error("Failed to execute integrity verification", e);
            log.error("Integrity verification result: execution error; user='{}'; error='{}'",
                    userName, e.getMessage());
            logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_FAILED,
                    "Integrity verification failed with error: " + e.getMessage());
            getReturnValue().getExecuteFailedMessages().add(errorMsg);
            setSucceeded(false);
        }
    }

    /**
     * Puts every file of every process the verification measured into the event list on a line
     * of its own: each that matched its baseline, each AIDE named as changed, removed or added,
     * and each that was not measured because it was not there.
     *
     * <p>An exit code says that something no longer matches; it does not say what, nor which
     * files were checked and found intact. Read from the same report the scheduled run is read
     * from, so that a verification says the same thing whoever asked for it.</p>
     *
     * @return how many files AIDE named in all, not how many were recorded one by one
     */
    private int reportChanges() {
        Optional<IntegrityVerification.Result> result = IntegrityVerification.readResult();
        List<IntegrityVerification.Change> changes = result.isPresent()
                ? IntegrityVerification.changesInLog(result.get().getLogFile())
                : List.of();
        List<VerificationFailureReport.Record> records =
                VerificationFailureReport.integrityRecords(IntegrityTargets.read(), changes);
        int recorded = Math.min(records.size(), MAX_REPORTED_FILES);
        for (VerificationFailureReport.Record record : records.subList(0, recorded)) {
            logAuditEvent(record.getType(), record.getMessage());
        }
        if (records.size() > recorded) {
            logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_WARNING,
                    "Integrity verification reported " + (records.size() - recorded)
                            + " further file(s); see "
                            + (result.isPresent() ? result.get().getLogFile() : "the AIDE report"));
        }
        return changes.size();
    }

    /** One record with every file that failed, in full; each is also recorded on its own just before. */
    private String summary(int exitCode) {
        String context = StartupSecurityAuditManager.summaryContext("webadmin", Instant.now()); //$NON-NLS-1$
        Optional<IntegrityVerification.Result> result = IntegrityVerification.readResult();
        List<IntegrityVerification.Change> changes = result.isPresent()
                ? IntegrityVerification.changesInLog(result.get().getLogFile())
                : List.of();
        return changes.isEmpty()
                ? VerificationFailureReport.integrityNotCarriedOut(context, exitCode)
                : VerificationFailureReport.integrityDetail(changes, IntegrityTargets.read(), context,
                        result.get().getLogFile());
    }

    private void logAuditEvent(AuditLogType type, String message) {
        AuditLog auditLog = new AuditLog(type, type.getSeverity());
        auditLog.setUserId(getCurrentUser().getId());
        auditLog.setUserName(getCurrentUser().getLoginName());
        auditLog.setMessage(message);
        auditLog.setCustomData(message);
        TransactionSupport.executeInNewTransaction(() -> {
            auditLogDao.save(auditLog);
            return null;
        });
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(Guid.SYSTEM,
                VdcObjectType.System,
                ActionGroup.AUDIT_LOG_MANAGEMENT));
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return getSucceeded() ? AuditLogType.INTEGRITY_VERIFICATION_COMPLETED : AuditLogType.INTEGRITY_VERIFICATION_FAILED;
    }
}
