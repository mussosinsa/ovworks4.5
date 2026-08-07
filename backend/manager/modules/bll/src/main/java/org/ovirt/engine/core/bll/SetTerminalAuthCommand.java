package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.TerminalAuthParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@NonTransactiveCommandAttribute
public class SetTerminalAuthCommand extends CommandBase<TerminalAuthParameters> {

    private static final Logger log = LoggerFactory.getLogger(SetTerminalAuthCommand.class);

    public SetTerminalAuthCommand(TerminalAuthParameters parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected void executeCommand() {
        try {
            TerminalAuthConfigUtils.updateSerialNumber(getParameters().getSerialNumber());
            setSucceeded(true);
        } catch (IOException ex) {
            log.error("Failed to update terminal auth serial number", ex); //$NON-NLS-1$
            getReturnValue().getExecuteFailedMessages().add(ex.getMessage());
            addCustomValue("CustomData", ex.getMessage()); //$NON-NLS-1$
            setSucceeded(false);
        }
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(MultiLevelAdministrationHandler.SYSTEM_OBJECT_ID,
                VdcObjectType.System,
                getActionType().getActionGroup()));
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return getSucceeded()
                ? AuditLogType.TERMINAL_AUTH_CONFIG_UPDATED
                : AuditLogType.TERMINAL_AUTH_CONFIG_UPDATE_FAILED;
    }
}
