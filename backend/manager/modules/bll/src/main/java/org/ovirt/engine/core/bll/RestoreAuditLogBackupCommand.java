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

public class RestoreAuditLogBackupCommand extends CommandBase<AuditLogBackupParameters> {

    private static final String SUDO_COMMAND = "/usr/bin/sudo"; //$NON-NLS-1$
    private static final String BACKUP_HELPER = "/usr/share/ovirt-engine/bin/audit-log-backup.py"; //$NON-NLS-1$

    public RestoreAuditLogBackupCommand(AuditLogBackupParameters parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected void executeCommand() {
        String backupPath = getParameters().getBackupPath();
        String selectedBackupFile = getParameters().getSelectedBackupFile();

        if (backupPath == null || backupPath.trim().isEmpty()) {
            getReturnValue().getExecuteFailedMessages().add("저장 위치가 비어 있습니다."); //$NON-NLS-1$
            setSucceeded(false);
            return;
        }
        if (selectedBackupFile == null || selectedBackupFile.trim().isEmpty()) {
            getReturnValue().getExecuteFailedMessages().add("복구할 감사기록 파일을 선택해 주세요."); //$NON-NLS-1$
            setSucceeded(false);
            return;
        }

        CommandResult restoreResult = runCommand(Arrays.asList(
                SUDO_COMMAND,
                "-n", //$NON-NLS-1$
                BACKUP_HELPER,
                "restore", //$NON-NLS-1$
                backupPath.trim(),
                selectedBackupFile.trim()));
        if (restoreResult.exitCode != 0) {
            getReturnValue().getExecuteFailedMessages().add("감사기록 복구 실패: " + restoreResult.output); //$NON-NLS-1$
            setSucceeded(false);
            return;
        }

        getReturnValue().setActionReturnValue(restoreResult.output);
        setSucceeded(true);
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(Guid.SYSTEM, VdcObjectType.System,
                ActionGroup.AUDIT_LOG_MANAGEMENT));
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return getSucceeded()
                ? AuditLogType.AUDIT_LOG_RESTORE_COMPLETED
                : AuditLogType.AUDIT_LOG_RESTORE_FAILED;
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
            output.append("실행 중 오류: ").append(e.getMessage()).append("\n"); //$NON-NLS-1$ //$NON-NLS-2$
            exitCode = 1;
        }
        return new CommandResult(exitCode, output.toString().trim());
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
