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
import org.ovirt.engine.core.common.action.EngineConfigValueParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.compat.Guid;

@NonTransactiveCommandAttribute
public class SetAaaJdbcSettingCommand<T extends EngineConfigValueParameters> extends CommandBase<T> {

    private static final List<String> EDITABLE_SETTINGS = Arrays.asList(
            "MAX_LOGIN_MINUTES", //$NON-NLS-1$
            "MAX_FAILURES_SINCE_SUCCESS", //$NON-NLS-1$
            "MINIMUM_RESPONSE_SECONDS"); //$NON-NLS-1$

    public SetAaaJdbcSettingCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected boolean validate() {
        if (!EDITABLE_SETTINGS.contains(getParameters().getKey()) || getParameters().getValue() == null) {
            return false;
        }
        try {
            return Integer.parseInt(getParameters().getValue()) > 0;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    @Override
    protected void executeCommand() {
        try {
            ProcessBuilder builder = new ProcessBuilder(
                    "ovirt-aaa-jdbc-tool", "settings", "set", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                    "--name=" + getParameters().getKey(), //$NON-NLS-1$
                    "--value=" + getParameters().getValue()); //$NON-NLS-1$
            builder.redirectErrorStream(true);
            Process process = builder.start();
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append('\n');
                }
            }
            int exitCode = process.waitFor();
            String text = output.toString().trim();
            getReturnValue().setActionReturnValue(text);
            if (exitCode == 0) {
                setSucceeded(true);
            } else {
                getReturnValue().getExecuteFailedMessages().add(text);
                setSucceeded(false);
            }
        } catch (Exception e) {
            log.error("Failed to update ovirt-aaa-jdbc setting", e); //$NON-NLS-1$
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
