package org.ovirt.engine.core.bll;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.EngineConfigValueParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.compat.Guid;

@NonTransactiveCommandAttribute
public class GetAaaJdbcSettingsCommand<T extends EngineConfigValueParameters> extends CommandBase<T> {

    public GetAaaJdbcSettingsCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected boolean validate() {
        String name = getParameters().getKey();
        return name != null && name.matches("[A-Z][A-Z0-9_]*"); //$NON-NLS-1$
    }

    @Override
    protected void executeCommand() {
        try {
            ProcessBuilder builder = new ProcessBuilder(
                    "ovirt-aaa-jdbc-tool", "settings", "show", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                    "--name=" + getParameters().getKey()); //$NON-NLS-1$
            builder.redirectErrorStream(true);
            Process process = builder.start();
            if (!process.waitFor(30, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                getReturnValue().getExecuteFailedMessages().add("사용자 환경 변수 조회 시간이 초과되었습니다."); //$NON-NLS-1$
                setSucceeded(false);
                return;
            }
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append('\n');
                }
            }
            int exitCode = process.exitValue();
            String text = output.toString().trim();
            getReturnValue().setActionReturnValue(text);
            if (exitCode == 0) {
                setSucceeded(true);
            } else {
                getReturnValue().getExecuteFailedMessages().add(text);
                setSucceeded(false);
            }
        } catch (Exception e) {
            log.error("Failed to read ovirt-aaa-jdbc settings", e); //$NON-NLS-1$
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
