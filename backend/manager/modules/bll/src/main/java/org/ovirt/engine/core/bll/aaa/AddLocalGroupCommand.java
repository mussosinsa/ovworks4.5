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
import org.ovirt.engine.core.common.action.AddLocalGroupParameters;
import org.ovirt.engine.core.common.businessentities.aaa.DbGroup;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.DbGroupDao;

/**
 * Creates a group in the internal authorization provider.
 *
 * <p>Until this existed an administrator could create a user from the administration portal but not
 * a group, so a group had to be made at a shell on the engine with ovirt-aaa-jdbc-tool before any
 * permission could be given to one. The dialog that grants permissions searches the provider, so a
 * group that was never created there was never offered - which looked like the dialog being broken
 * rather than like there being no groups.</p>
 *
 * <p>It is the counterpart of {@link AddLocalUserCommand} and works the same way: the provider's own
 * tool creates the group, and the engine then takes a copy of the row so the group appears in the
 * list straight away. The copy carries the identifier the provider assigned, for the reason set out
 * on {@link AaaJdbcTool#principalIdOf(String)} - anything else and granting a permission
 * writes a second row for the same group.</p>
 */
public class AddLocalGroupCommand extends CommandBase<AddLocalGroupParameters> {

    /** The only realm this command creates groups in. */
    private static final String INTERNAL_AUTHZ = "internal-authz"; //$NON-NLS-1$

    /** The same names the provider's tool accepts, which is what a group may be called. */
    private static final String NAME_PATTERN = "[A-Za-z0-9._-]+"; //$NON-NLS-1$

    @Inject
    private DbGroupDao dbGroupDao;

    public AddLocalGroupCommand(AddLocalGroupParameters parameters, CommandContext context) {
        super(parameters, context);
    }

    @Override
    protected boolean validate() {
        addCustomValue("TargetGroup", value(getParameters().getGroupName())); //$NON-NLS-1$
        String name = value(getParameters().getGroupName()).trim();
        return !name.isEmpty() && name.matches(NAME_PATTERN);
    }

    @Override
    protected void executeCommand() {
        String groupName = getParameters().getGroupName().trim();
        String operator = getCurrentUser() == null ? "unknown" : getCurrentUser().getLoginName(); //$NON-NLS-1$
        log.info("그룹 추가 실행 시작; target='{}'; operator='{}'; command='ovirt-aaa-jdbc-tool group add'",
                groupName, operator);
        try {
            CommandResult add = run("group", "add", groupName); //$NON-NLS-1$ //$NON-NLS-2$
            if (add.exitCode != 0) {
                log.error("그룹 추가 실행 실패; target='{}'; operator='{}'; exitCode={}; output='{}'",
                        groupName, operator, add.exitCode, add.output);
                getReturnValue().getExecuteFailedMessages().add(add.output);
                setSucceeded(false);
                return;
            }

            DbGroup group = dbGroupDao.getByNameAndDomain(groupName, INTERNAL_AUTHZ);
            if (group == null) {
                group = recordGroup(groupName);
            }
            if (group != null) {
                setActionReturnValue(group.getId());
            }
            setSucceeded(true);
            log.info("그룹 추가 실행 결과 정상; target='{}'; operator='{}'", groupName, operator);
        } catch (Exception e) {
            log.error("그룹 추가 실행 오류; target='{}'; operator='{}'", groupName, operator, e);
            getReturnValue().getExecuteFailedMessages().add(e.getMessage());
            setSucceeded(false);
        }
    }

    /**
     * Writes the engine's own row for the group just created.
     *
     * @return the row written, or null when the provider did not report an identifier for it - in
     *         which case none is written. The group exists either way, and the engine takes a copy
     *         the first time it is given a permission; a row filed under the wrong identifier would
     *         instead become a second group that only looks like this one.
     */
    private DbGroup recordGroup(String groupName) throws Exception {
        CommandResult show = run("group", "show", groupName); //$NON-NLS-1$ //$NON-NLS-2$
        String externalId = show.exitCode == 0 ? AaaJdbcTool.principalIdOf(show.output) : null;
        if (externalId == null) {
            log.warn("그룹 추가: 그룹 목록 행 생략; target='{}'; 사유='ovirt-aaa-jdbc-tool group show 가"
                    + " principal id 를 주지 않음'; exitCode={}; output='{}'",
                    groupName, show.exitCode, show.output);
            return null;
        }

        DbGroup group = new DbGroup();
        group.setId(Guid.newGuid());
        group.setExternalId(externalId);
        group.setName(groupName);
        group.setDomain(INTERNAL_AUTHZ);
        group.setNamespace("*"); //$NON-NLS-1$
        dbGroupDao.save(group);
        return group;
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

    private static String value(String text) {
        return text == null ? "" : text; //$NON-NLS-1$
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return getSucceeded() ? AuditLogType.LOCAL_GROUP_CREATED : AuditLogType.LOCAL_GROUP_CREATE_FAILED;
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(MultiLevelAdministrationHandler.SYSTEM_OBJECT_ID,
                VdcObjectType.System, getActionType().getActionGroup()));
    }

    protected static class CommandResult {
        protected final int exitCode;
        protected final String output;

        protected CommandResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }
}
