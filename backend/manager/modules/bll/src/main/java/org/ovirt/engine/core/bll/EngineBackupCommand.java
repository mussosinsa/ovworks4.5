package org.ovirt.engine.core.bll;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.AuditLogBackupParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.compat.Guid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EngineBackupCommand extends CommandBase<AuditLogBackupParameters> {

    private static final Logger log = LoggerFactory.getLogger(EngineBackupCommand.class);
    private static final String SUDO_COMMAND = "/usr/bin/sudo"; //$NON-NLS-1$
    private static final String ENGINE_BACKUP_COMMAND = "/usr/share/ovirt-engine/bin/engine-backup-root.sh"; //$NON-NLS-1$

    public EngineBackupCommand(AuditLogBackupParameters parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected void executeCommand() {
        String backupPath = getParameters().getBackupPath();
        if (backupPath == null || backupPath.trim().isEmpty()) {
            getReturnValue().getExecuteFailedMessages().add("저장 위치가 비어 있습니다."); //$NON-NLS-1$
            setSucceeded(false);
            return;
        }

        CommandResult result = runCommand(Arrays.asList(
                SUDO_COMMAND, "-n", ENGINE_BACKUP_COMMAND, backupPath.trim())); //$NON-NLS-1$
        getReturnValue().setActionReturnValue(result.output);
        if (result.exitCode == 0) {
            setSucceeded(true);
        } else {
            if (containsEngineNotificationFailure(result.output)) {
                getReturnValue().getExecuteFailedMessages()
                        .add("engine-backup 실행 중 엔진 알림에 실패했습니다."); //$NON-NLS-1$
            } else {
                getReturnValue().getExecuteFailedMessages().add("engine-backup 실패 (종료 코드: " //$NON-NLS-1$
                        + result.exitCode + ")\n" + result.output); //$NON-NLS-1$
            }
            setSucceeded(false);
        }
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(Guid.SYSTEM, VdcObjectType.System,
                ActionGroup.AUDIT_LOG_MANAGEMENT));
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return getSucceeded() ? AuditLogType.ENGINE_BACKUP_COMPLETED : AuditLogType.ENGINE_BACKUP_FAILED;
    }

    private CommandResult runCommand(List<String> command) {
        StringBuilder output = new StringBuilder();
        int exitCode;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n"); //$NON-NLS-1$
                }
            }
            exitCode = process.waitFor();
        } catch (Exception e) {
            log.error("Failed to execute engine backup command", e);
            output.append("실행 중 오류: ").append(e.getMessage()).append("\n"); //$NON-NLS-1$ //$NON-NLS-2$
            exitCode = 1;
        }
        return new CommandResult(exitCode, output.toString().trim());
    }

    private boolean containsEngineNotificationFailure(String output) {
        if (output == null) {
            return false;
        }
        return output.contains("Failed notifying engine"); //$NON-NLS-1$
    }

    private static final class CommandResult {
        private final int exitCode;
        private final String output;

        private CommandResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }
}
