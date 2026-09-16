package org.ovirt.engine.core.bll;

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
 * Command to execute security audit script and log results
 */
public class SecurityAuditCommand<T extends ActionParametersBase> extends CommandBase<T> {

    private static final Logger log = LoggerFactory.getLogger(SecurityAuditCommand.class);

    @Inject
    private AuditLogDao auditLogDao;

    public SecurityAuditCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected boolean validate() {
        return true;
    }

    @Override
    protected void executeCommand() {
        if (SecurityAuditRunner.isRunning()) {
            reportAlreadyRunning();
            return;
        }
        executeSecurityAudit();
    }

    private void reportAlreadyRunning() {
        String errorMsg = "보안 감사가 이미 실행 중입니다.";
        log.warn("Security audit result: rejected because another audit is running; user='{}'",
                getCurrentUser().getLoginName());
        logAuditEvent(AuditLogType.SECURITY_AUDIT_WARNING, "Security audit request ignored: already running");
        getReturnValue().getExecuteFailedMessages().add(errorMsg);
        setSucceeded(false);
    }

    private void executeSecurityAudit() {
        String userName = getCurrentUser().getLoginName();
        log.info("Security audit requested by user '{}'; runner='{}'", userName, SecurityAuditRunner.RUNNER);
        if (!SecurityAuditRunner.exists()) {
            String errorMsg = "보안 감사 실행기를 찾을 수 없습니다: " + SecurityAuditRunner.RUNNER;
            log.error("Security audit runner not found: {}", SecurityAuditRunner.RUNNER);
            log.error("Security audit result: runner not found; user='{}'", userName);
            logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED,
                    "Security audit runner not found: " + SecurityAuditRunner.RUNNER);
            getReturnValue().getExecuteFailedMessages().add(errorMsg);
            setSucceeded(false);
            return;
        }
        if (!SecurityAuditRunner.isAvailable()) {
            String errorMsg = "보안 감사 실행기를 실행할 수 없습니다: " + SecurityAuditRunner.RUNNER;
            log.error("Security audit runner is not executable: {}", SecurityAuditRunner.RUNNER);
            log.error("Security audit result: runner is not executable; user='{}'", userName);
            logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED,
                    "Security audit runner is not executable: " + SecurityAuditRunner.RUNNER);
            getReturnValue().getExecuteFailedMessages().add(errorMsg);
            setSucceeded(false);
            return;
        }

        logAuditEvent(AuditLogType.SECURITY_AUDIT_STARTED, "Security audit started");
        log.info("보안검증 실행 시작; user='{}'", userName);
        log.info("Security audit started by user '{}'", userName);

        SecurityAuditRunner.Run run = SecurityAuditRunner.run("security", "webadmin"); //$NON-NLS-1$ //$NON-NLS-2$
        for (String line : run.getOutput().split("\n")) { //$NON-NLS-1$
            log.info("Security Audit: {}", line);
        }
        getReturnValue().setActionReturnValue(run.getOutput());

        switch (run.getOutcome()) {
            case BUSY:
                reportAlreadyRunning();
                return;
            case TIMED_OUT:
                String timeoutMsg = "보안 감사가 " + SecurityAuditRunner.TIMEOUT_MINUTES + "분 내에 완료되지 않았습니다.";
                log.error(timeoutMsg);
                log.error("Security audit result: timed out; user='{}'; timeoutMinutes={}",
                        userName, SecurityAuditRunner.TIMEOUT_MINUTES);
                logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED, "Security audit timed out");
                getReturnValue().getExecuteFailedMessages().add(timeoutMsg);
                setSucceeded(false);
                return;
            case PASSED:
                log.info("보안검증 실행 결과 정상; user='{}'", userName);
                log.info("Security audit result: success; user='{}'; exitCode={}", userName, run.getExitCode());
                logAuditEvent(AuditLogType.SECURITY_AUDIT_COMPLETED, "Security audit completed successfully");
                setSucceeded(true);
                return;
            default:
                String errorMsg = "보안 감사 실패 (종료 코드: " + run.getExitCode() + ")";
                log.error("보안검증 실행 실패; user='{}'; exitCode={}", userName, run.getExitCode());
                log.error("Security audit result: failure; user='{}'; exitCode={}", userName, run.getExitCode());
                logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED,
                        "Security audit failed with exit code: " + run.getExitCode());
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
        return getSucceeded() ? AuditLogType.SECURITY_AUDIT_COMPLETED : AuditLogType.SECURITY_AUDIT_FAILED;
    }
}
