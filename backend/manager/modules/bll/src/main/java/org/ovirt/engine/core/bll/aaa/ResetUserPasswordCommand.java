package org.ovirt.engine.core.bll.aaa;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.bll.CommandBase;
import org.ovirt.engine.core.bll.MultiLevelAdministrationHandler;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.UserPasswordResetParameters;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.common.businessentities.aaa.UserPasswordHistoryEntry;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.DbUserDao;
import org.ovirt.engine.core.dao.UserPasswordHistoryDao;
import org.ovirt.engine.core.uutils.security.PasswordHistoryCryptor;
import org.ovirt.engine.core.uutils.security.PasswordHistoryEntry;
import org.ovirt.engine.core.uutils.security.PasswordPolicy;
import org.ovirt.engine.core.uutils.security.PasswordPolicyValidator;
import org.ovirt.engine.core.uutils.security.PasswordPolicyViolation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ResetUserPasswordCommand extends CommandBase<UserPasswordResetParameters> {

    private static final Logger log = LoggerFactory.getLogger(ResetUserPasswordCommand.class);

    /**
     * Password validity applied when the user is not forced to change the password on the
     * next login.
     */
    private static final int PASSWORD_VALIDITY_YEARS = 1;

    /** Number of history entries read for the reuse checks and kept by the cleanup. */
    private static final int HISTORY_LIMIT = 32;

    /** Name of the environment variable carrying the password to ovirt-aaa-jdbc-tool. */
    private static final String PASSWORD_ENV_VAR = "OVIRT_ENGINE_AAA_NEW_PASSWORD";

    @Inject
    private DbUserDao dbUserDao;

    @Inject
    private UserPasswordHistoryDao userPasswordHistoryDao;

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
    protected boolean validate() {
        String newPassword = getParameters().getNewPassword();

        // Check that password is provided
        if (newPassword == null || newPassword.trim().isEmpty()) {
            addValidationMessage(EngineMessage.ACTION_TYPE_FAILED_PASSWORD_MUST_BE_SPECIFIED);
            return false;
        }

        // Check that the user exists in the database
        DbUser user = dbUserDao.get(getParameters().getUserId());
        if (user == null) {
            addValidationMessage(EngineMessage.USER_MUST_EXIST_IN_DB);
            return false;
        }
        addAuditContext(user.getLoginName());

        // Check that it's not a group
        if (user.isGroup()) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_PASSWORD_CANNOT_BE_RESET_FOR_GROUP);
        }

        return validatePasswordPolicy(user, newPassword);
    }

    /**
     * Runs the configured password policy, including the reuse checks, and reports every
     * violated rule as a validation failure so the caller learns what to correct.
     */
    private boolean validatePasswordPolicy(DbUser user, String newPassword) {
        PasswordPolicy policy = PasswordPolicyResolver.resolve();

        List<PasswordPolicyViolation> violations =
                PasswordPolicyValidator.validate(policy, newPassword, user.getLoginName());

        if (violations.isEmpty() && policy.isHistoryRequired()) {
            Optional<PasswordPolicyViolation> reuse = PasswordPolicyValidator.validateHistory(
                    policy,
                    newPassword,
                    readHistory(principalKey(user)),
                    Instant.now());
            reuse.ifPresent(violations::add);
        }

        if (violations.isEmpty()) {
            return true;
        }

        getReturnValue().getValidationMessages().addAll(PasswordPolicyValidator.toMessages(violations));
        return false;
    }

    private List<PasswordHistoryEntry> readHistory(String principal) {
        List<PasswordHistoryEntry> history = new ArrayList<>();
        for (UserPasswordHistoryEntry entry : userPasswordHistoryDao.getByPrincipal(principal, HISTORY_LIMIT)) {
            if (entry.getPasswordHash() != null && entry.getChangeDate() != null) {
                history.add(new PasswordHistoryEntry(entry.getPasswordHash(), entry.getChangeDate().toInstant()));
            }
        }
        return history;
    }

    private static String principalKey(DbUser user) {
        return PasswordHistoryCryptor.principalKey(user.getLoginName(), user.getDomain());
    }

    @Override
    protected void executeCommand() {
        DbUser user = dbUserDao.get(getParameters().getUserId());
        if (user == null) {
            setSucceeded(false);
            return;
        }

        String username = user.getLoginName();
        addAuditContext(username);
        String newPassword = getParameters().getNewPassword();
        boolean forceChangeOnFirstLogin = PasswordPolicyResolver.isForceChangeOnFirstLogin();
        String operator = getCurrentUser() == null ? "unknown" : getCurrentUser().getLoginName(); //$NON-NLS-1$
        log.info("패스워드 리셋 실행 시작; target='{}'; operator='{}'", username, operator);

        try {
            // Execute ovirt-aaa-jdbc-tool user password-reset command. The password is handed
            // over through the environment, a command line argument would expose it to every
            // local user through /proc/<pid>/cmdline.
            ProcessBuilder processBuilder = new ProcessBuilder(
                "ovirt-aaa-jdbc-tool",
                "user",
                "password-reset",
                username,
                "--password-valid-to=" + passwordValidTo(forceChangeOnFirstLogin),
                "--password=env:" + PASSWORD_ENV_VAR
            );
            Map<String, String> environment = processBuilder.environment();
            environment.put(PASSWORD_ENV_VAR, newPassword);

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
                log.info("패스워드 리셋 실행 결과 정상; target='{}'; operator='{}'", username, operator);
                log.info("Successfully reset password for user: {}. Change on first login: {}",
                        username, forceChangeOnFirstLogin);
                recordPasswordHistory(user, newPassword);
                setSucceeded(true);
            } else {
                log.error("패스워드 리셋 실행 실패; target='{}'; operator='{}'; exitCode={}",
                        username, operator, exitCode);
                log.error("Failed to reset password for user: {}. Exit code: {}. Output: {}",
                        username, exitCode, output.toString());
                // Extract and add detailed error message for the user
                String errorMessage = parsePasswordPolicyError(output.toString());
                getReturnValue().getExecuteFailedMessages().add(errorMessage);
                setSucceeded(false);
            }

        } catch (IOException | InterruptedException e) {
            log.error("패스워드 리셋 실행 오류; target='{}'; operator='{}'", username, operator, e);
            log.error("Error executing ovirt-aaa-jdbc-tool for user: {}", username, e);
            getReturnValue().getExecuteFailedMessages().add(e.getMessage());
            setSucceeded(false);
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void addAuditContext(String targetUser) {
        String sessionId = getParameters().getSessionId();
        if (sessionId == null && getContext() != null) {
            sessionId = getContext().getEngineContext().getSessionId();
        }
        String sourceIp = sessionId == null ? null : getSessionDataContainer().getSourceIp(sessionId);
        addCustomValue("TargetUser", targetUser); //$NON-NLS-1$
        addCustomValue("SourceIP", StringUtils.defaultIfEmpty(sourceIp, "unknown")); //$NON-NLS-1$ //$NON-NLS-2$
    }

    /**
     * @param forceChangeOnFirstLogin when true the password is stored already expired, which
     *        makes authn report expired credentials on the next login and sso redirect the
     *        user to the password change page before any other page is served
     */
    static String passwordValidTo(boolean forceChangeOnFirstLogin) {
        ZonedDateTime validTo = forceChangeOnFirstLogin
                ? ZonedDateTime.now().minusMinutes(1)
                : ZonedDateTime.now().plusYears(PASSWORD_VALIDITY_YEARS);
        return validTo.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssX"));
    }

    /**
     * Remembers the password that was just set so the reuse policies can see it later. A
     * failure here must not undo a password that is already in effect, it is logged instead.
     */
    private void recordPasswordHistory(DbUser user, String newPassword) {
        PasswordPolicy policy = PasswordPolicyResolver.resolve();
        if (!policy.isHistoryRequired()) {
            return;
        }
        String principal = principalKey(user);
        try {
            Date now = new Date();
            userPasswordHistoryDao.save(new UserPasswordHistoryEntry(
                    principal,
                    PasswordHistoryCryptor.hash(newPassword),
                    now));
            userPasswordHistoryDao.cleanup(
                    principal,
                    Date.from(ZonedDateTime.now().minusMonths(Math.max(policy.getHistoryMonths(), 1)).toInstant()),
                    HISTORY_LIMIT);
        } catch (RuntimeException ex) {
            log.error("Unable to record the password history of '{}': {}", principal, ex.getMessage());
            log.debug("Exception", ex);
        }
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
    protected void setActionMessageParameters() {
        addValidationMessage(EngineMessage.VAR__ACTION__RESET);
        addValidationMessage(EngineMessage.VAR__TYPE__USER);
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return getSucceeded() ? AuditLogType.LOCAL_USER_PASSWORD_RESET
                : AuditLogType.LOCAL_USER_PASSWORD_RESET_FAILED;
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(
                MultiLevelAdministrationHandler.SYSTEM_OBJECT_ID,
                VdcObjectType.System,
                getActionType().getActionGroup()));
    }
}
