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
import org.ovirt.engine.core.common.action.UpdateLocalUserParameters;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.dao.DbUserDao;

public class UpdateLocalUserCommand extends CommandBase<UpdateLocalUserParameters> {
    @Inject
    private DbUserDao dbUserDao;

    public UpdateLocalUserCommand(UpdateLocalUserParameters parameters, CommandContext context) {
        super(parameters, context);
    }

    @Override
    protected boolean validate() {
        DbUser user = dbUserDao.get(getParameters().getId());
        if (user == null) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_USER_NOT_EXISTS);
        }
        addCustomValue("TargetUser", user.getLoginName()); //$NON-NLS-1$
        return !user.isGroup() && "internal-authz".equals(user.getDomain()); //$NON-NLS-1$
    }

    @Override
    protected void executeCommand() {
        DbUser user = dbUserDao.get(getParameters().getId());
        try {
            CommandResult result = run(userEditArguments(
                    user.getLoginName(), getParameters().getFirstName(),
                    getParameters().getLastName(), getParameters().getEmail()));
            if (result.exitCode != 0) {
                getReturnValue().getExecuteFailedMessages().add(result.output);
                setSucceeded(false);
                return;
            }
            user.setFirstName(value(getParameters().getFirstName()));
            user.setLastName(value(getParameters().getLastName()));
            user.setEmail(value(getParameters().getEmail()));
            dbUserDao.update(user);
            setSucceeded(true);
        } catch (Exception exception) {
            log.error("Failed to update local user '{}'", user.getLoginName(), exception);
            getReturnValue().getExecuteFailedMessages().add(exception.getMessage());
            setSucceeded(false);
        }
    }

    private static String value(String value) {
        return value == null ? "" : value.trim(); //$NON-NLS-1$
    }

    static String[] userEditArguments(String loginName, String firstName, String lastName, String email) {
        return new String[] {
                "user", "edit", loginName, //$NON-NLS-1$ //$NON-NLS-2$
                "--attribute=firstName=" + value(firstName), //$NON-NLS-1$
                "--attribute=lastName=" + value(lastName), //$NON-NLS-1$
                "--attribute=email=" + value(email) //$NON-NLS-1$
        };
    }

    protected CommandResult run(String... arguments) throws Exception {
        String[] command = new String[arguments.length + 1];
        command[0] = "ovirt-aaa-jdbc-tool"; //$NON-NLS-1$
        System.arraycopy(arguments, 0, command, 1, arguments.length);
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
        return getSucceeded() ? AuditLogType.LOCAL_USER_UPDATED : AuditLogType.LOCAL_USER_UPDATE_FAILED;
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(MultiLevelAdministrationHandler.SYSTEM_OBJECT_ID,
                VdcObjectType.System, getActionType().getActionGroup()));
    }
}
