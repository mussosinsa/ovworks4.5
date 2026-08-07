package org.ovirt.engine.core.bll;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.AuditLogBackupParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.compat.Guid;

public class ListAuditLogBackupsCommand extends CommandBase<AuditLogBackupParameters> {

    public ListAuditLogBackupsCommand(AuditLogBackupParameters parameters, CommandContext cmdContext) {
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

        Path directory = Paths.get(backupPath.trim()).normalize();
        if (!Files.isDirectory(directory)) {
            getReturnValue().getExecuteFailedMessages().add("저장 위치를 찾을 수 없습니다: " + directory); //$NON-NLS-1$
            setSucceeded(false);
            return;
        }

        try (Stream<Path> files = Files.list(directory)) {
            List<String> archives = files
                    .filter(Files::isRegularFile)
                    .map(Path::getFileName)
                    .map(Path::toString)
                    .filter(name -> name.endsWith(".tar.gz")) //$NON-NLS-1$
                    .sorted(Comparator.reverseOrder())
                    .collect(Collectors.toList());
            getReturnValue().setActionReturnValue(archives);
            setSucceeded(true);
        } catch (Exception e) {
            getReturnValue().getExecuteFailedMessages().add("감사기록 목록 조회 실패: " + e.getMessage()); //$NON-NLS-1$
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
        return AuditLogType.UNASSIGNED;
    }
}
