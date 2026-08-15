package org.ovirt.engine.core.bll.aaa;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.List;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.MultiLevelAdministrationHandler;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.IdParameters;
import org.ovirt.engine.core.common.action.PermissionsOperationsParameters;
import org.ovirt.engine.core.common.businessentities.Permission;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.DbUserDao;
import org.ovirt.engine.core.dao.PermissionDao;

public class RemoveUserCommand<T extends IdParameters> extends UserCommandBase<T> {

    private static final String INTERNAL_AUTHZ = "internal-authz"; //$NON-NLS-1$

    @Inject
    private PermissionDao permissionDao;
    @Inject
    private DbUserDao dbUserDao;

    /**
     * Constructor for command creation when compensation is applied on startup
     */
    public RemoveUserCommand(Guid commandId) {
        super(commandId);
    }

    public RemoveUserCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return getSucceeded() ? AuditLogType.USER_REMOVE_ADUSER : AuditLogType.USER_FAILED_REMOVE_ADUSER;

    }

    @Override
    protected void executeCommand() {
        // Get the identifier of the user to be removed from the parameters:
        Guid id = getParameters().getId();
        DbUser user = dbUserDao.get(id);

        if (INTERNAL_AUTHZ.equals(user.getDomain()) && !deleteLocalUser(user)) {
            return;
        }

        // Delete all the permissions of the user:
        // TODO: This should be done without invoking the command to avoid the overhead.
        for (Permission permission : permissionDao.getAllDirectPermissionsForAdElement(id)) {
            PermissionsOperationsParameters tempVar = new PermissionsOperationsParameters(permission);
            tempVar.setShouldBeLogged(false);
            runInternalActionWithTasksContext(ActionType.RemovePermission, tempVar);
        }

        // Delete the user itself:
        dbUserDao.remove(id);

        setSucceeded(true);
    }

    private boolean deleteLocalUser(DbUser user) {
        String username = user.getLoginName();
        String operator = getCurrentUser() == null ? "unknown" : getCurrentUser().getLoginName(); //$NON-NLS-1$
        log.info("로컬 사용자 삭제 실행 시작; target='{}'; operator='{}'; "
                        + "command='ovirt-aaa-jdbc-tool user delete'", username, operator);
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(
                    "ovirt-aaa-jdbc-tool", "user", "delete", username); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append('\n');
                }
            }
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                String result = output.toString().trim();
                log.error("로컬 사용자 삭제 실행 실패; target='{}'; operator='{}'; exitCode={}; output='{}'",
                        username, operator, exitCode, result);
                getReturnValue().getExecuteFailedMessages().add(result);
                setSucceeded(false);
                return false;
            }
            log.info("로컬 사용자 삭제 실행 결과 정상; target='{}'; operator='{}'", username, operator);
            return true;
        } catch (Exception e) {
            log.error("로컬 사용자 삭제 실행 오류; target='{}'; operator='{}'", username, operator, e);
            getReturnValue().getExecuteFailedMessages().add(e.getMessage());
            setSucceeded(false);
            return false;
        }
    }

    @Override
    protected boolean validate() {
        // Get the identifier of the user to be removed:
        Guid id = getParameters().getId();

        // Check that the current user isn't trying to remove himself:
        if (getCurrentUser().getId().equals(id)) {
            addValidationMessage(EngineMessage.USER_CANNOT_REMOVE_HIMSELF);
            return false;
        }

        // Check that the user exists in the database:
        DbUser dbUser = dbUserDao.get(id);
        if (dbUser == null) {
            addValidationMessage(EngineMessage.USER_MUST_EXIST_IN_DB);
            return false;
        }

        return true;
    }

    @Override
    protected void setActionMessageParameters() {
        addValidationMessage(EngineMessage.VAR__ACTION__REMOVE);
        addValidationMessage(EngineMessage.VAR__TYPE__USER);
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        // Not needed for admin operations.
        return Collections.singletonList(new PermissionSubject(MultiLevelAdministrationHandler.SYSTEM_OBJECT_ID,
                VdcObjectType.System,
                getActionType().getActionGroup()));
    }
}
