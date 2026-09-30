package org.ovirt.engine.core.bll;

import java.util.Collections;
import java.util.List;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.AuditLogBackupParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.compat.Guid;

/**
 * Measures the audit record storage for the protection tab and returns it as the rows described by
 * {@link AuditStorageSnapshot#toRows()}. The backup path typed on the tab, when there is one, is
 * measured as well so the administrator sees the free space before backing up or restoring.
 */
@NonTransactiveCommandAttribute
public class GetAuditLogStorageStatusCommand extends CommandBase<AuditLogBackupParameters> {

    @Inject
    private AuditLogCapacityMonitor capacityMonitor;

    public GetAuditLogStorageStatusCommand(AuditLogBackupParameters parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected void executeCommand() {
        try {
            AuditStorageSnapshot snapshot = capacityMonitor.refresh(getParameters().getBackupPath());
            getReturnValue().setActionReturnValue(snapshot.toRows());
            setSucceeded(true);
        } catch (RuntimeException exception) {
            log.error("Unable to measure the audit record storage", exception);
            getReturnValue().getExecuteFailedMessages().add("감사기록 저장소 용량 조회 실패: " //$NON-NLS-1$
                    + exception.getMessage());
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
