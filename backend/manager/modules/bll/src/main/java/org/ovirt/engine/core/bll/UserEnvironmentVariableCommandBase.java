package org.ovirt.engine.core.bll;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.List;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.EngineConfigValueParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.compat.Guid;

abstract class UserEnvironmentVariableCommandBase<T extends EngineConfigValueParameters> extends CommandBase<T> {

    UserEnvironmentVariableCommandBase(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    protected boolean hasReadableKey() {
        return getParameters().getKey() != null
                && getParameters().getKey().trim().matches("[A-Z][A-Z0-9_]*"); //$NON-NLS-1$
    }

    protected boolean hasWritableKey() {
        return hasReadableKey();
    }

    protected void executeTool(String... arguments) {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(arguments);
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append('\n');
                }
            }
            int exitCode = process.waitFor();
            String result = output.toString().trim();
            getReturnValue().setActionReturnValue(result);
            setSucceeded(exitCode == 0);
            if (exitCode != 0) {
                getReturnValue().getExecuteFailedMessages().add(result);
            }
        } catch (Exception e) {
            log.error("Failed to manage user environment variable", e); //$NON-NLS-1$
            getReturnValue().getExecuteFailedMessages().add(e.getMessage());
            setSucceeded(false);
        }
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(Guid.SYSTEM, VdcObjectType.System,
                ActionGroup.CONFIGURE_ENGINE));
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return AuditLogType.UNASSIGNED;
    }
}
