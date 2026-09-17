package org.ovirt.engine.core.bll;

import java.io.BufferedReader;
import java.io.InputStreamReader;
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

    /** As many files as the scheduled run records one by one, so the two read the same. */
    private static final int MAX_REPORTED_CHANGES = 50;

    @Inject
    private AuditLogDao auditLogDao;

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
                getReturnValue().getExecuteFailedMessages().add(errorMsg);
                setSucceeded(false);
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
     * Puts each file AIDE named into the event list on a line of its own.
     *
     * <p>An exit code says that something no longer matches; it does not say what. That answer
     * was only in a report on the engine host, which is not where the person who pressed the
     * button is looking. Read from the same report the scheduled run is read from, so that a
     * verification says the same thing whoever asked for it.</p>
     *
     * @return how many files AIDE named in all, not how many were recorded one by one
     */
    private int reportChanges() {
        Optional<IntegrityVerification.Result> result = IntegrityVerification.readResult();
        if (result.isEmpty()) {
            return 0;
        }
        List<IntegrityVerification.Change> changes =
                IntegrityVerification.changesInLog(result.get().getLogFile());
        int recorded = Math.min(changes.size(), MAX_REPORTED_CHANGES);
        for (IntegrityVerification.Change change : changes.subList(0, recorded)) {
            logAuditEvent(change.getKind() == IntegrityVerification.Change.Kind.REMOVED
                    ? AuditLogType.INTEGRITY_VERIFICATION_FILE_MISSING
                    : AuditLogType.INTEGRITY_VERIFICATION_FILE_MODIFIED,
                    change.describe());
        }
        if (changes.size() > recorded) {
            logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_WARNING,
                    "Integrity verification reported " + (changes.size() - recorded)
                            + " further file(s); see " + result.get().getLogFile());
        }
        return changes.size();
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
