package org.ovirt.engine.core.bll;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.List;

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
                        "Integrity verification completed successfully");
                setSucceeded(true);
            } else {
                String errorMsg = "무결성 검사 실패 (종료 코드: " + exitCode + ")";
                log.error("무결성 검사 실행 실패; user='{}'; exitCode={}", userName, exitCode);
                log.error("Integrity verification result: failure; user='{}'; exitCode={}", userName, exitCode);
                logAuditEvent(AuditLogType.INTEGRITY_VERIFICATION_FAILED,
                        "Integrity verification failed with exit code: " + exitCode);
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
