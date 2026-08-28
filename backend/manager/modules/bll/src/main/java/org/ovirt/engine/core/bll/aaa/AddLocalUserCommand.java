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

public class AddLocalUserCommand extends CommandBase<AddLocalUserParameters> {
    private static final String PASSWORD_ENV = "OVIRT_ENGINE_AAA_INITIAL_PASSWORD"; //$NON-NLS-1$

    @Inject
    private DbUserDao dbUserDao;

    public AddLocalUserCommand(AddLocalUserParameters parameters, CommandContext context) {
        super(parameters, context);
    }

    @Override
    protected boolean validate() {
        addCustomValue("TargetUser", value(getParameters().getUserName())); //$NON-NLS-1$
        if (isBlank(getParameters().getUserName()) || isBlank(getParameters().getPassword())) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_PASSWORD_MUST_BE_SPECIFIED);
        }
        return getParameters().getUserName().matches("[A-Za-z0-9._-]+"); //$NON-NLS-1$
    }

    @Override
    protected void executeCommand() {
        String userName = getParameters().getUserName().trim();
        String operator = getCurrentUser() == null ? "unknown" : getCurrentUser().getLoginName(); //$NON-NLS-1$
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
            CommandResult reset = run("user", "password-reset", userName, //$NON-NLS-1$ //$NON-NLS-2$
                    "--password-valid-to=" + value(getParameters().getPasswordValidTo()), //$NON-NLS-1$
                    "--password=env:" + PASSWORD_ENV); //$NON-NLS-1$
            if (reset.exitCode != 0) {
                fail(userName, operator, "password-reset", reset); //$NON-NLS-1$
                rollbackAaaUser(userName, operator);
                return;
            }

            DbUser user = dbUserDao.getByUsernameAndDomain(userName, "internal-authz"); //$NON-NLS-1$
            if (user == null) {
                user = new DbUser();
                user.setId(Guid.newGuid());
                user.setExternalId(userName);
                user.setLoginName(userName);
                user.setDomain("internal-authz"); //$NON-NLS-1$
                user.setNamespace("*"); //$NON-NLS-1$
                user.setFirstName(value(getParameters().getFirstName()));
                user.setLastName(value(getParameters().getLastName()));
                user.setDepartment(""); //$NON-NLS-1$
                dbUserDao.save(user);
            }
            setActionReturnValue(user.getId());
            setSucceeded(true);
            log.info("사용자 추가 실행 결과 정상; target='{}'; operator='{}'", userName, operator);
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
