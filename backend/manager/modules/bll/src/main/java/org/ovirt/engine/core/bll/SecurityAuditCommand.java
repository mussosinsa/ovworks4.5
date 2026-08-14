package org.ovirt.engine.core.bll;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

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
    private static final String SECURITY_AUDIT_RUNNER =
            "/usr/share/ovirt-engine/bin/ovirt-engine-security-verification-runner.sh"; //$NON-NLS-1$
    private static final long SECURITY_AUDIT_TIMEOUT_MINUTES = 11;
    private static final AtomicBoolean SECURITY_AUDIT_RUNNING = new AtomicBoolean();

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
        if (!SECURITY_AUDIT_RUNNING.compareAndSet(false, true)) {
            String errorMsg = "보안 감사가 이미 실행 중입니다.";
            log.warn("Security audit result: rejected because another audit is running; user='{}'",
                    getCurrentUser().getLoginName());
            logAuditEvent(AuditLogType.SECURITY_AUDIT_WARNING, "Security audit request ignored: already running");
            getReturnValue().getExecuteFailedMessages().add(errorMsg);
            setSucceeded(false);
            return;
        }

        try {
            executeSecurityAudit();
        } finally {
            SECURITY_AUDIT_RUNNING.set(false);
        }
    }

    private void executeSecurityAudit() {
        String userName = getCurrentUser().getLoginName();
        log.info("Security audit requested by user '{}'; runner='{}'", userName, SECURITY_AUDIT_RUNNER);
        // Check if script exists and is executable
        java.io.File scriptFile = new java.io.File(SECURITY_AUDIT_RUNNER);
        if (!scriptFile.exists()) {
            String errorMsg = "보안 감사 실행기를 찾을 수 없습니다: " + SECURITY_AUDIT_RUNNER;
            log.error("Security audit runner not found: {}", SECURITY_AUDIT_RUNNER);
            log.error("Security audit result: runner not found; user='{}'", userName);
            logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED, "Security audit runner not found: " + SECURITY_AUDIT_RUNNER);
            getReturnValue().getExecuteFailedMessages().add(errorMsg);
            setSucceeded(false);
            return;
        }
        if (!scriptFile.canExecute()) {
            String errorMsg = "보안 감사 실행기를 실행할 수 없습니다: " + SECURITY_AUDIT_RUNNER;
            log.error("Security audit runner is not executable: {}", SECURITY_AUDIT_RUNNER);
            log.error("Security audit result: runner is not executable; user='{}'", userName);
            logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED, "Security audit runner is not executable: " + SECURITY_AUDIT_RUNNER);
            getReturnValue().getExecuteFailedMessages().add(errorMsg);
            setSucceeded(false);
            return;
        }

        logAuditEvent(AuditLogType.SECURITY_AUDIT_STARTED, "Security audit started");
        log.info("보안검증 실행 시작; user='{}'", userName);
        log.info("Security audit started by user '{}'", userName);

        try {
            Path outputFile = Files.createTempFile("ovirt-security-audit-", ".log");
            try {
                // Execute the script directly so its bash shebang is honored. Invoking it through
                // `sh` creates an unnecessary shell process and can run the bash-specific script
                // with an incompatible shell.
                ProcessBuilder processBuilder = new ProcessBuilder(SECURITY_AUDIT_RUNNER, "security", "webadmin");
                processBuilder.redirectErrorStream(true);
                processBuilder.redirectOutput(outputFile.toFile());
                Process process = processBuilder.start();
                // The audit must never wait for an interactive child command (for example, su)
                // to receive input from the engine process.
                process.getOutputStream().close();

                if (!process.waitFor(SECURITY_AUDIT_TIMEOUT_MINUTES, TimeUnit.MINUTES)) {
                    terminateProcessTree(process);
                    String errorMsg = "보안 감사가 " + SECURITY_AUDIT_TIMEOUT_MINUTES + "분 내에 완료되지 않았습니다.";
                    log.error(errorMsg);
                    log.error("Security audit result: timed out; user='{}'; timeoutMinutes={}",
                            userName, SECURITY_AUDIT_TIMEOUT_MINUTES);
                    logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED, "Security audit timed out");
                    getReturnValue().getExecuteFailedMessages().add(errorMsg);
                    setSucceeded(false);
                    return;
                }

                // The process output is redirected to a file so a full pipe cannot block the audit process.
                StringBuilder output = new StringBuilder();
                for (String line : Files.readAllLines(outputFile, StandardCharsets.UTF_8)) {
                    output.append(line).append("\n");
                    log.info("Security Audit: {}", line);
                }

                int exitCode = process.exitValue();

                if (exitCode == 0) {
                    log.info("보안검증 실행 결과 정상; user='{}'", userName);
                    log.info("Security audit result: success; user='{}'; exitCode={}", userName, exitCode);
                    logAuditEvent(AuditLogType.SECURITY_AUDIT_COMPLETED, "Security audit completed successfully");
                    setSucceeded(true);
                } else {
                    String errorMsg = "보안 감사 실패 (종료 코드: " + exitCode + ")";
                    log.error("보안검증 실행 실패; user='{}'; exitCode={}", userName, exitCode);
                    log.error("Security audit result: failure; user='{}'; exitCode={}", userName, exitCode);
                    logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED,
                        "Security audit failed with exit code: " + exitCode);
                    getReturnValue().getExecuteFailedMessages().add(errorMsg);
                    setSucceeded(false);
                }

                // Store the output in return value
                getReturnValue().setActionReturnValue(output.toString());
            } finally {
                Files.deleteIfExists(outputFile);
            }

        } catch (Exception e) {
            String errorMsg = "보안 감사 실행 중 오류 발생: " + e.getMessage();
            log.error("Failed to execute security audit script", e);
            log.error("Security audit result: execution error; user='{}'; error='{}'", userName, e.getMessage());
            logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED,
                "Security audit failed with error: " + e.getMessage());
            getReturnValue().getExecuteFailedMessages().add(errorMsg);
            setSucceeded(false);
        }
    }

    private void terminateProcessTree(Process process) throws InterruptedException {
        // Shell scripts can create child processes. Destroying only the top-level shell leaves
        // those children running and causes the UI action to remain in the running state.
        process.toHandle().descendants().forEach(ProcessHandle::destroy);
        process.destroy();
        if (!process.waitFor(5, TimeUnit.SECONDS)) {
            process.toHandle().descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
            process.waitFor();
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
