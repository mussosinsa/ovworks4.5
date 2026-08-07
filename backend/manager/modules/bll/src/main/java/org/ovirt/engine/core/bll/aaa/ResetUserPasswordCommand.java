package org.ovirt.engine.core.bll.aaa;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.CommandBase;
import org.ovirt.engine.core.bll.MultiLevelAdministrationHandler;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.UserPasswordResetParameters;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.DbUserDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ResetUserPasswordCommand extends CommandBase<UserPasswordResetParameters> {

    private static final Logger log = LoggerFactory.getLogger(ResetUserPasswordCommand.class);
    private static final int MIN_PASSWORD_LENGTH = 12;

    @Inject
    private DbUserDao dbUserDao;

    /**
     * Constructor for command creation when compensation is applied on startup
     */
    public ResetUserPasswordCommand(Guid commandId) {
        super(commandId);
    }

    public ResetUserPasswordCommand(UserPasswordResetParameters parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected void executeCommand() {
        Guid userId = getParameters().getUserId();
        String newPassword = getParameters().getNewPassword();

        DbUser user = dbUserDao.get(userId);
        if (user == null) {
            setSucceeded(false);
            return;
        }

        String username = user.getLoginName();

        String complexityError = getPasswordComplexityValidationError(newPassword);
        if (complexityError != null) {
            getReturnValue().getExecuteFailedMessages().add(complexityError);
            setSucceeded(false);
            return;
        }

        try {
            // Calculate password valid-to date (10 years from now)
            ZonedDateTime validTo = ZonedDateTime.now().plusYears(10);
            String validToStr = validTo.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssX"));

            // Execute ovirt-aaa-jdbc-tool user password-reset command
            ProcessBuilder processBuilder = new ProcessBuilder(
                "ovirt-aaa-jdbc-tool",
                "user",
                "password-reset",
                username,
                "--password-valid-to=" + validToStr,
                "--password=pass:" + newPassword
            );

            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            // Read the output
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            int exitCode = process.waitFor();

            if (exitCode == 0) {
                log.info("Successfully reset password for user: {}", username);
                setSucceeded(true);
            } else {
                log.error("Failed to reset password for user: {}. Exit code: {}. Output: {}",
                        username, exitCode, output.toString());
                // Extract and add detailed error message for the user
                String errorMessage = parsePasswordPolicyError(output.toString());
                getReturnValue().getExecuteFailedMessages().add(errorMessage);
                setSucceeded(false);
            }

        } catch (IOException | InterruptedException e) {
            log.error("Error executing ovirt-aaa-jdbc-tool for user: {}", username, e);
            getReturnValue().getExecuteFailedMessages().add(e.getMessage());
            setSucceeded(false);
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private String getPasswordComplexityValidationError(String password) {
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            return String.format("패스워드는 최소 %d자리 이상이어야 합니다.", MIN_PASSWORD_LENGTH);
        }
        if (!password.matches(".*[0-9].*")) {
            return "패스워드에는 숫자가 최소 1개 이상 포함되어야 합니다.";
        }
        if (!password.matches(".*[A-Z].*")) {
            return "패스워드에는 영문 대문자가 최소 1개 이상 포함되어야 합니다.";
        }
        if (!password.matches(".*[a-z].*")) {
            return "패스워드에는 영문 소문자가 최소 1개 이상 포함되어야 합니다.";
        }
        if (!password.matches(".*[^A-Za-z0-9].*")) {
            return "패스워드에는 특수문자가 최소 1개 이상 포함되어야 합니다.";
        }
        return null;
    }

    /**
     * Parse the output from ovirt-aaa-jdbc-tool to extract password policy error messages.
     * @param output the raw output from the command
     * @return a user-friendly error message
     */
    private String parsePasswordPolicyError(String output) {
        if (output == null || output.isEmpty()) {
            return "패스워드 변경에 실패했습니다.";
        }

        StringBuilder errorMsg = new StringBuilder();

        // Check for common password policy violations
        if (output.contains("too short") || output.contains("minimum length")) {
            errorMsg.append("패스워드가 너무 짧습니다. 최소 길이 요구사항을 충족해야 합니다.\n");
        }
        if (output.contains("uppercase") || output.contains("capital")) {
            errorMsg.append("패스워드에 대문자가 포함되어야 합니다.\n");
        }
        if (output.contains("lowercase")) {
            errorMsg.append("패스워드에 소문자가 포함되어야 합니다.\n");
        }
        if (output.contains("digit") || output.contains("number")) {
            errorMsg.append("패스워드에 숫자가 포함되어야 합니다.\n");
        }
        if (output.contains("special") || output.contains("symbol")) {
            errorMsg.append("패스워드에 특수문자가 포함되어야 합니다.\n");
        }
        if (output.contains("history") || output.contains("previously used")) {
            errorMsg.append("이전에 사용한 패스워드는 사용할 수 없습니다.\n");
        }
        if (output.contains("dictionary") || output.contains("common word")) {
            errorMsg.append("사전에 있는 단어는 패스워드로 사용할 수 없습니다.\n");
        }
        if (output.contains("username") || output.contains("user name")) {
            errorMsg.append("패스워드에 사용자 이름이 포함될 수 없습니다.\n");
        }

        // If no specific error was found, return the raw output (cleaned up)
        if (errorMsg.length() == 0) {
            // Clean up the output - remove Java tool options and extract meaningful message
            String cleanedOutput = output
                    .replaceAll("Picked up JAVA_TOOL_OPTIONS:.*\\n?", "")
                    .replaceAll(".*SEVERE:.*?:", "")
                    .replaceAll(".*Exception.*?:", "")
                    .trim();
            if (!cleanedOutput.isEmpty()) {
                return "패스워드 정책 오류: " + cleanedOutput;
            }
            return "패스워드 정책을 충족하지 않습니다. 보안 요구사항을 확인하세요.";
        }

        return errorMsg.toString().trim();
    }

    @Override
    protected boolean validate() {
        Guid userId = getParameters().getUserId();
        String newPassword = getParameters().getNewPassword();

        // Check that password is provided
        if (newPassword == null || newPassword.trim().isEmpty()) {
            addValidationMessage(EngineMessage.ACTION_TYPE_FAILED_PASSWORD_MUST_BE_SPECIFIED);
            return false;
        }

        // Check that the user exists in the database
        DbUser user = dbUserDao.get(userId);
        if (user == null) {
            addValidationMessage(EngineMessage.USER_MUST_EXIST_IN_DB);
            return false;
        }

        // Check that it's not a group
        if (user.isGroup()) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_PASSWORD_CANNOT_BE_RESET_FOR_GROUP);
        }

        return true;
    }

    @Override
    protected void setActionMessageParameters() {
        addValidationMessage(EngineMessage.VAR__ACTION__RESET);
        addValidationMessage(EngineMessage.VAR__TYPE__USER);
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return getSucceeded() ? AuditLogType.USER_PASSWORD_CHANGED : AuditLogType.USER_PASSWORD_CHANGE_FAILED;
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(
                MultiLevelAdministrationHandler.SYSTEM_OBJECT_ID,
                VdcObjectType.System,
                getActionType().getActionGroup()));
    }
}
