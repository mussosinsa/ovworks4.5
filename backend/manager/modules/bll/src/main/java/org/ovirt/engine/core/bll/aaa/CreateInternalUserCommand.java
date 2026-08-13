package org.ovirt.engine.core.bll.aaa;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.CommandBase;
import org.ovirt.engine.core.bll.MultiLevelAdministrationHandler;
import org.ovirt.engine.core.bll.NonTransactiveCommandAttribute;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.CreateInternalUserParameters;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.DbUserDao;

@NonTransactiveCommandAttribute
public class CreateInternalUserCommand extends CommandBase<CreateInternalUserParameters> {
    private static final String PASSWORD_ENV = "OVIRT_AAA_USER_PASSWORD"; //$NON-NLS-1$

    @Inject
    private DbUserDao dbUserDao;

    public CreateInternalUserCommand(CreateInternalUserParameters parameters, CommandContext context) {
        super(parameters, context);
    }

    @Override
    protected boolean validate() {
        return getParameters().getUsername() != null && !getParameters().getUsername().trim().isEmpty()
                && getParameters().getPassword() != null && !getParameters().getPassword().isEmpty();
    }

    @Override
    protected void executeCommand() {
        try {
            run("user", "add", getParameters().getUsername(), //$NON-NLS-1$ //$NON-NLS-2$
                    "--attribute=firstName=" + getParameters().getFirstName(), //$NON-NLS-1$
                    "--attribute=lastName=" + getParameters().getLastName()); //$NON-NLS-1$
            ProcessBuilder reset = command("user", "password-reset", getParameters().getUsername(), //$NON-NLS-1$ //$NON-NLS-2$
                    "--password-valid-to=" + getParameters().getPasswordValidTo(), //$NON-NLS-1$
                    "--password=env:" + PASSWORD_ENV); //$NON-NLS-1$
            reset.environment().put(PASSWORD_ENV, getParameters().getPassword());
            execute(reset);

            DbUser user = new DbUser();
            user.setId(Guid.newGuid());
            user.setExternalId(getParameters().getUsername());
            user.setLoginName(getParameters().getUsername());
            user.setFirstName(getParameters().getFirstName());
            user.setLastName(getParameters().getLastName());
            user.setDomain("internal-authz"); //$NON-NLS-1$
            user.setNamespace("*"); //$NON-NLS-1$
            dbUserDao.save(user);
            setSucceeded(true);
        } catch (IOException | InterruptedException e) {
            getReturnValue().getExecuteFailedMessages().add(e.getMessage());
            setSucceeded(false);
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
        }
    }

    private void run(String... args) throws IOException, InterruptedException { execute(command(args)); }
    private ProcessBuilder command(String... args) {
        String[] command = new String[args.length + 1]; command[0] = "ovirt-aaa-jdbc-tool"; //$NON-NLS-1$
        System.arraycopy(args, 0, command, 1, args.length); return new ProcessBuilder(command).redirectErrorStream(true);
    }
    private void execute(ProcessBuilder builder) throws IOException, InterruptedException {
        Process process = builder.start();
        if (process.waitFor() != 0) throw new IOException("ovirt-aaa-jdbc-tool failed"); //$NON-NLS-1$
    }

    @Override public AuditLogType getAuditLogTypeValue() { return AuditLogType.USER_ADD; }
    @Override public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(MultiLevelAdministrationHandler.SYSTEM_OBJECT_ID,
                VdcObjectType.System, getActionType().getActionGroup()));
    }
}
