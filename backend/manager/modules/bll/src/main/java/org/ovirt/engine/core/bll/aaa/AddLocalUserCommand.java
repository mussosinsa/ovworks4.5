package org.ovirt.engine.core.bll.aaa;

import java.io.BufferedReader;
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
import org.ovirt.engine.core.common.action.AddLocalUserParameters;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.DbUserDao;
import org.ovirt.engine.core.dao.UserPasswordHistoryDao;
import org.ovirt.engine.core.uutils.security.PasswordPolicy;
import org.ovirt.engine.core.uutils.security.PasswordPolicyValidator;
import org.ovirt.engine.core.uutils.security.PasswordPolicyViolation;

public class AddLocalUserCommand extends CommandBase<AddLocalUserParameters> {
    private static final String PASSWORD_ENV = "OVIRT_ENGINE_AAA_INITIAL_PASSWORD"; //$NON-NLS-1$

    /** The only realm this command creates accounts in. */
    private static final String INTERNAL_AUTHZ = "internal-authz"; //$NON-NLS-1$

    /**
     * The ovirt-aaa-jdbc-tool switch that leaves the password rules to whoever is calling it.
     * This command has already run the engine's policy in {@code validatePasswordPolicy()},
     * which is the policy the administrator configures and the one whose messages reach the user.
     */
    private static final String ENGINE_POLICY_IS_AUTHORITATIVE = "--force"; //$NON-NLS-1$

    @Inject
    private DbUserDao dbUserDao;

    @Inject
    private UserPasswordHistoryDao userPasswordHistoryDao;

    public AddLocalUserCommand(AddLocalUserParameters parameters, CommandContext context) {
        super(parameters, context);
    }

    @Override
    protected boolean validate() {
        addCustomValue("TargetUser", value(getParameters().getUserName())); //$NON-NLS-1$
        if (isBlank(getParameters().getUserName()) || isBlank(getParameters().getPassword())) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_PASSWORD_MUST_BE_SPECIFIED);
        }
        if (!getParameters().getUserName().matches("[A-Za-z0-9._-]+")) { //$NON-NLS-1$
            return false;
        }
        return validatePasswordPolicy();
    }

    /**
     * Runs the configured password policy over the initial password, and reports every violated
     * rule so the administrator learns what to correct.
     *
     * <p>This runs in validate rather than in execute on purpose: a rejected password must not
     * leave an AAA account behind. The password is only handed to ovirt-aaa-jdbc-tool once the
     * policy has accepted it.</p>
     */
    private boolean validatePasswordPolicy() {
        PasswordPolicy policy = passwordPolicy();
        List<PasswordPolicyViolation> violations = PasswordPolicyValidator.validate(
                policy, getParameters().getPassword(), getParameters().getUserName());
        if (violations.isEmpty()) {
            // a login name that was used before keeps its history, so an account removed and
            // created again cannot start from a password the reuse rules have already retired
            UserPasswordHistoryStore.checkReuse(
                    userPasswordHistoryDao, policy, principalKey(), getParameters().getPassword())
                    .ifPresent(violations::add);
        }
        if (violations.isEmpty()) {
            return true;
        }
        getReturnValue().getValidationMessages().addAll(PasswordPolicyValidator.toMessages(violations));
        return false;
    }

    private String principalKey() {
        return UserPasswordHistoryStore.principalKey(value(getParameters().getUserName()), INTERNAL_AUTHZ);
    }

    /** Overridable so that a test can exercise the command without the engine configuration. */
    protected PasswordPolicy passwordPolicy() {
        return PasswordPolicyResolver.resolve();
    }

    @Override
    protected void executeCommand() {
        String userName = getParameters().getUserName().trim();
        String operator = getCurrentUser() == null ? "unknown" : getCurrentUser().getLoginName(); //$NON-NLS-1$
        boolean forceChangeOnFirstLogin = isForceChangeOnFirstLogin();
        boolean aaaUserCreated = false;
        log.info("사용자 추가 실행 시작; target='{}'; operator='{}'; command='ovirt-aaa-jdbc-tool user add'",
                userName, operator);
        try {
            CommandResult add = run("user", "add", userName, //$NON-NLS-1$ //$NON-NLS-2$
                    "--attribute=firstName=" + value(getParameters().getFirstName()), //$NON-NLS-1$
                    "--attribute=lastName=" + value(getParameters().getLastName())); //$NON-NLS-1$
            if (add.exitCode != 0) {
                fail(userName, operator, "user add", add); //$NON-NLS-1$
                return;
            }
            aaaUserCreated = true;
            // The tool is told not to run its own password rules over this password;
            // validatePasswordPolicy() has already run the engine's, and the two are not the
            // same set. The tool refuses any password whose only special character falls outside
            // its fixed list of ASCII punctuation - a tilde, a space, anything non-ASCII - while
            // the engine accepts every character that is not a letter or a digit. With both in
            // place such a password passes the dialog, is refused here, and the account this
            // command has just created is rolled back. One policy decides, and it is the
            // engine's: the one an administrator can configure, and the one whose messages the
            // user is shown.
            CommandResult reset = run("user", "password-reset", userName, //$NON-NLS-1$ //$NON-NLS-2$
                    "--password-valid-to=" + initialPasswordValidTo(forceChangeOnFirstLogin), //$NON-NLS-1$
                    ENGINE_POLICY_IS_AUTHORITATIVE,
                    "--password=env:" + PASSWORD_ENV); //$NON-NLS-1$
            if (reset.exitCode != 0) {
                fail(userName, operator, "password-reset", reset); //$NON-NLS-1$
                rollbackAaaUser(userName, operator);
                return;
            }

            DbUser user = dbUserDao.getByUsernameAndDomain(userName, INTERNAL_AUTHZ);
            if (user == null) {
                user = recordUser(userName);
            }
            // Without this the account has no history at all, and the first password reset would
            // be free to set the initial password again - which is exactly what the two reuse
            // rules forbid.
            recordInitialPassword();
            // Null when the engine kept no row of its own - see recordUser. The account exists and
            // the command succeeded; there is simply no engine id to hand back yet, and the caller
            // is a dialog that closes on success rather than one that uses the id.
            if (user != null) {
                setActionReturnValue(user.getId());
            }
            setSucceeded(true);
            log.info("사용자 추가 실행 결과 정상; target='{}'; operator='{}'; 최초 로그인 시 변경={}",
                    userName, operator, forceChangeOnFirstLogin);
        } catch (Exception e) {
            log.error("사용자 추가 실행 오류; target='{}'; operator='{}'", userName, operator, e);
            getReturnValue().getExecuteFailedMessages().add(e.getMessage());
            setSucceeded(false);
            if (aaaUserCreated) {
                rollbackAaaUser(userName, operator);
            }
        }
    }

    /**
     * Writes the engine's own row for the account just created, so that it appears in the user list
     * straight away rather than only once somebody grants it a permission.
     *
     * <p>The row has to carry the identifier the authorization provider gave the account, because
     * that is the one everything else matches on. AddPermissionCommand looks an existing user up by
     * it, and a row filed under anything else is not found - so granting a permission would write a
     * second row for the same person, which nothing prevents: the table is unique on
     * (domain, external_id), and two rows with different external ids are two different users as
     * far as it is concerned. The account would then be listed twice, with its permissions on one
     * row and its password history on the other. Until this asked the tool for the identifier, the
     * login name was stored in its place and that is exactly what happened.</p>
     *
     * @return the row written, or null when the identifier could not be read - in which case none
     *         is written at all. No row is a small thing: the account is in the authorization
     *         provider, and the engine takes a copy the first time it is given a permission or logs
     *         in. A row under the wrong identifier is the duplicate this exists to avoid.
     */
    private DbUser recordUser(String userName) throws Exception {
        CommandResult show = run("user", "show", userName); //$NON-NLS-1$ //$NON-NLS-2$
        String externalId = show.exitCode == 0 ? AaaJdbcTool.principalIdOf(show.output) : null;
        if (externalId == null) {
            log.warn("사용자 추가: 사용자 목록 행 생략; target='{}'; 사유='ovirt-aaa-jdbc-tool user show 가"
                    + " principal id 를 주지 않음'; exitCode={}; output='{}'",
                    userName, show.exitCode, show.output);
            return null;
        }

        DbUser user = new DbUser();
        user.setId(Guid.newGuid());
        user.setExternalId(externalId);
        user.setLoginName(userName);
        user.setDomain(INTERNAL_AUTHZ);
        user.setNamespace("*"); //$NON-NLS-1$
        user.setFirstName(value(getParameters().getFirstName()));
        user.setLastName(value(getParameters().getLastName()));
        user.setDepartment(""); //$NON-NLS-1$
        dbUserDao.save(user);
        return user;
    }

    /** Overridable so that a test can exercise the command without the injected DAO. */
    protected void recordInitialPassword() {
        UserPasswordHistoryStore.record(
                userPasswordHistoryDao, passwordPolicy(), principalKey(), getParameters().getPassword());
    }

    /** Overridable so that a test can exercise the command without the engine configuration. */
    protected boolean isForceChangeOnFirstLogin() {
        return PasswordPolicyResolver.isForceChangeOnFirstLogin();
    }

    /**
     * A new local account answers to the same setting as a password reset. When it is on the
     * account has to go through the credential-change flow before it can obtain an authenticated
     * Engine session; when it is off the assigned password is usable straight away.
     */
    static String initialPasswordValidTo(boolean forceChangeOnFirstLogin) {
        return InitialPasswordValidity.validTo(forceChangeOnFirstLogin);
    }

    /**
     * Remove the AAA identity created by this command when a later initialization step fails.
     * This prevents an unusable account without its requested initial password from remaining.
     */
    private void rollbackAaaUser(String userName, String operator) {
        try {
            CommandResult delete = run("user", "delete", userName); //$NON-NLS-1$ //$NON-NLS-2$
            if (delete.exitCode == 0) {
                log.info("사용자 추가 롤백 완료; target='{}'; operator='{}'", userName, operator);
            } else {
                log.error("사용자 추가 롤백 실패; target='{}'; operator='{}'; exitCode={}; output='{}'",
                        userName, operator, delete.exitCode, delete.output);
                getReturnValue().getExecuteFailedMessages().add(
                        "Failed to remove partially created user: " + delete.output); //$NON-NLS-1$
            }
        } catch (Exception rollbackError) {
            log.error("사용자 추가 롤백 오류; target='{}'; operator='{}'", userName, operator, rollbackError);
            getReturnValue().getExecuteFailedMessages().add(
                    "Failed to remove partially created user: " + rollbackError.getMessage()); //$NON-NLS-1$
        }
    }

    protected CommandResult run(String... arguments) throws Exception {
        String[] command = new String[arguments.length + 1];
        command[0] = "ovirt-aaa-jdbc-tool"; //$NON-NLS-1$
        System.arraycopy(arguments, 0, command, 1, arguments.length);
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.environment().put(PASSWORD_ENV, getParameters().getPassword());
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

    private void fail(String user, String operator, String step, CommandResult result) {
        log.error("사용자 추가 실행 실패; target='{}'; operator='{}'; step='{}'; exitCode={}; output='{}'",
                user, operator, step, result.exitCode, result.output);
        getReturnValue().getExecuteFailedMessages().add(result.output);
        setSucceeded(false);
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static String value(String value) {
        return value == null ? "" : value.trim();
    }

    protected static class CommandResult {
        final int exitCode;
        final String output;
        protected CommandResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return getSucceeded() ? AuditLogType.LOCAL_USER_CREATED : AuditLogType.LOCAL_USER_CREATE_FAILED;
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(MultiLevelAdministrationHandler.SYSTEM_OBJECT_ID,
                VdcObjectType.System, getActionType().getActionGroup()));
    }
}
