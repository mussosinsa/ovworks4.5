package org.ovirt.engine.core.bll.aaa;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.List;

import org.ovirt.engine.core.bll.CommandBase;
import org.ovirt.engine.core.bll.MultiLevelAdministrationHandler;
import org.ovirt.engine.core.bll.NonTransactiveCommandAttribute;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.CreateLocalUserParameters;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@NonTransactiveCommandAttribute
public class CreateLocalUserCommand extends CommandBase<CreateLocalUserParameters> {

    private static final Logger log = LoggerFactory.getLogger(CreateLocalUserCommand.class);

    public CreateLocalUserCommand(CreateLocalUserParameters parameters, CommandContext commandContext) {
        super(parameters, commandContext);
    }

    @Override
    protected void executeCommand() {
        try {
            CommandResult addResult = runCommand(
                    "ovirt-aaa-jdbc-tool", "user", "add", getParameters().getUsername(), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                    "--attribute=firstName=" + getParameters().getFirstName(), //$NON-NLS-1$
                    "--attribute=lastName=" + getParameters().getLastName()); //$NON-NLS-1$
            if (addResult.exitCode != 0) {
                fail(addResult.output);
                return;
            }

            CommandResult passwordResult = runCommand(
                    "ovirt-aaa-jdbc-tool", "user", "password-reset", getParameters().getUsername(), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                    "--password-valid-to=" + nullToEmpty(getParameters().getPasswordValidTo()), //$NON-NLS-1$
                    "--password=pass:" + getParameters().getPassword()); //$NON-NLS-1$
            if (passwordResult.exitCode != 0) {
                fail(passwordResult.output);
                return;
            }
            setSucceeded(true);
        } catch (IOException | InterruptedException e) {
            log.error("Failed to create local user '{}'", getParameters().getUsername(), e); //$NON-NLS-1$
            getReturnValue().getExecuteFailedMessages().add(e.getMessage());
            setSucceeded(false);
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private CommandResult runCommand(String... command) throws IOException, InterruptedException {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append('\n');
            }
        }
        return new CommandResult(process.waitFor(), output.toString().trim());
    }

    private void fail(String output) {
        log.error("Local user creation failed for '{}': {}", getParameters().getUsername(), output); //$NON-NLS-1$
        getReturnValue().getExecuteFailedMessages().add(
                output.isEmpty() ? "사용자 추가에 실패했습니다." : output); //$NON-NLS-1$
        setSucceeded(false);
    }

    @Override
    protected boolean validate() {
        CreateLocalUserParameters parameters = getParameters();
        if (isBlank(parameters.getUsername()) || isBlank(parameters.getFirstName())
                || isBlank(parameters.getLastName()) || isBlank(parameters.getPassword())) {
            addValidationMessage(EngineMessage.ACTION_TYPE_FAILED_PASSWORD_MUST_BE_SPECIFIED);
            return false;
        }
        return true;
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value; //$NON-NLS-1$
    }

    @Override
    protected void setActionMessageParameters() {
        addValidationMessage(EngineMessage.VAR__ACTION__ADD);
        addValidationMessage(EngineMessage.VAR__TYPE__USER);
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return getSucceeded() ? AuditLogType.USER_ADD : AuditLogType.USER_FAILED_ADD_ADUSER;
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(
                MultiLevelAdministrationHandler.SYSTEM_OBJECT_ID,
                VdcObjectType.System,
                getActionType().getActionGroup()));
    }

    private static class CommandResult {
        private final int exitCode;
        private final String output;

        private CommandResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }
}
