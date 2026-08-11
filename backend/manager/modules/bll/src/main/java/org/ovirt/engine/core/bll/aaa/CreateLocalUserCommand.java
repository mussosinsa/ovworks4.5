package org.ovirt.engine.core.bll.aaa;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.List;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.CommandBase;
import org.ovirt.engine.core.bll.MultiLevelAdministrationHandler;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.CreateLocalUserParameters;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.dao.DbUserDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CreateLocalUserCommand extends CommandBase<CreateLocalUserParameters> {

    private static final Logger log = LoggerFactory.getLogger(CreateLocalUserCommand.class);
    private static final String INTERNAL_AUTHZ = "internal-authz"; //$NON-NLS-1$
    private static final int MIN_PASSWORD_LENGTH = 6;

    @Inject
    private DbUserDao dbUserDao;

    public CreateLocalUserCommand(CreateLocalUserParameters parameters, CommandContext commandContext) {
        super(parameters, commandContext);
    }

    @Override
    protected void executeCommand() {
        boolean userAdded = false;
        try {
            CommandResult addResult = runCommand(
                    "ovirt-aaa-jdbc-tool", //$NON-NLS-1$
                    "user", //$NON-NLS-1$
                    "add", //$NON-NLS-1$
                    getParameters().getUsername(),
                    "--attribute=firstName=" + getParameters().getFirstName(), //$NON-NLS-1$
                    "--attribute=lastName=" + getParameters().getLastName()); //$NON-NLS-1$
            if (addResult.exitCode != 0) {
                fail(addResult.output);
                return;
            }
            userAdded = true;

            CommandResult passwordResult = runCommand(
                    "ovirt-aaa-jdbc-tool", //$NON-NLS-1$
                    "user", //$NON-NLS-1$
                    "password-reset", //$NON-NLS-1$
                    getParameters().getUsername(),
                    "--password-valid-to=" + nullToEmpty(getParameters().getPasswordValidTo()), //$NON-NLS-1$
                    "--password=pass:" + getParameters().getPassword()); //$NON-NLS-1$
            if (passwordResult.exitCode != 0) {
                removePartiallyCreatedUser();
                fail(passwordResult.output);
                return;
            }

            CommandResult showResult = runCommand(
                    "ovirt-aaa-jdbc-tool", //$NON-NLS-1$
                    "user", //$NON-NLS-1$
                    "show", //$NON-NLS-1$
                    getParameters().getUsername());
            String externalId = extractExternalId(showResult);
            if (showResult.exitCode != 0 || externalId == null) {
                removePartiallyCreatedUser();
                fail(showResult.output);
                return;
            }

            dbUserDao.save(createDbUser(externalId));
            setSucceeded(true);
        } catch (IOException | InterruptedException | RuntimeException e) {
            log.error("Failed to create local user '{}'", getParameters().getUsername(), e); //$NON-NLS-1$
            if (userAdded) {
                removePartiallyCreatedUser();
            }
            getReturnValue().getExecuteFailedMessages().add(
                    e.getMessage() == null ? "사용자 추가에 실패했습니다." : e.getMessage()); //$NON-NLS-1$
            setSucceeded(false);
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private String extractExternalId(CommandResult showResult) {
        for (String line : showResult.output.split("\\r?\\n")) { //$NON-NLS-1$
            String trimmed = line.trim();
            if (trimmed.startsWith("ID:")) { //$NON-NLS-1$
                String externalId = trimmed.substring("ID:".length()).trim(); //$NON-NLS-1$
                return externalId.isEmpty() ? null : externalId;
            }
        }
        return null;
    }

    private DbUser createDbUser(String externalId) {
        DbUser user = new DbUser();
        user.setExternalId(externalId);
        user.setDomain(INTERNAL_AUTHZ);
        user.setNamespace("*"); //$NON-NLS-1$
        user.setLoginName(getParameters().getUsername());
        user.setFirstName(getParameters().getFirstName());
        user.setLastName(getParameters().getLastName());
        return user;
    }

    private void removePartiallyCreatedUser() {
        try {
            CommandResult removeResult = runCommand(
                    "ovirt-aaa-jdbc-tool", //$NON-NLS-1$
                    "user", //$NON-NLS-1$
                    "delete", //$NON-NLS-1$
                    getParameters().getUsername());
            if (removeResult.exitCode != 0) {
                log.error("Failed to remove partially created local user '{}': {}", //$NON-NLS-1$
                        getParameters().getUsername(), removeResult.output);
                addCleanupFailureMessage();
            }
        } catch (IOException | InterruptedException e) {
            log.error("Failed to remove partially created local user '{}'", //$NON-NLS-1$
                    getParameters().getUsername(), e);
            addCleanupFailureMessage();
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void addCleanupFailureMessage() {
        getReturnValue().getExecuteFailedMessages().add(
                "부분적으로 생성된 사용자를 삭제하지 못했습니다. 해당 사용자를 삭제한 후 다시 시도해 주세요."); //$NON-NLS-1$
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
        addCustomValue("NewUserName", parameters.getUsername()); //$NON-NLS-1$
        if (isBlank(parameters.getUsername()) || isBlank(parameters.getFirstName())
                || isBlank(parameters.getLastName()) || isBlank(parameters.getPassword())) {
            addValidationMessage(EngineMessage.ACTION_TYPE_FAILED_PASSWORD_MUST_BE_SPECIFIED);
            return false;
        }
        if (parameters.getPassword().length() < MIN_PASSWORD_LENGTH) {
            getReturnValue().getExecuteFailedMessages().add("패스워드는 최소 6자리 이상이어야 합니다."); //$NON-NLS-1$
            return false;
        }
        if (parameters.getUsername().equalsIgnoreCase(parameters.getPassword())) {
            getReturnValue().getExecuteFailedMessages().add("사용자 계정과 동일한 패스워드는 사용할 수 없습니다."); //$NON-NLS-1$
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
