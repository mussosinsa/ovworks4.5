package org.ovirt.engine.core.bll.aaa;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.CommandBase;
import org.ovirt.engine.core.bll.MultiLevelAdministrationHandler;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.ActionParametersBase;
import org.ovirt.engine.core.common.action.UpdateLocalGroupMembersParameters;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.common.businessentities.aaa.SessionEndReason;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogableImpl;
import org.ovirt.engine.core.dao.DbUserDao;

/**
 * Adds users to, and removes users from, a group of the internal authorization provider.
 *
 * <p>Until this existed a group's members could only be changed at a shell on the engine with
 * {@code ovirt-aaa-jdbc-tool group-manage}. The provider's own tool does the change here as well,
 * one user at a time, and each change is recorded in the audit log on its own - added, removed,
 * or the reason it was not.</p>
 *
 * <p>The engine reads which groups a user is in when the user logs in, so a change of membership
 * would otherwise only take effect at the next login: a user taken out of a group would keep what
 * the group gave them for as long as their session lasted. The sessions of every user whose
 * membership changed are therefore ended, and the next login picks up the change.</p>
 */
public class UpdateLocalGroupMembersCommand extends CommandBase<UpdateLocalGroupMembersParameters> {

    /** The realm of the provider whose groups this command changes. */
    static final String INTERNAL_AUTHZ = "internal-authz"; //$NON-NLS-1$

    /** What the provider's tool accepts as a group or a user name. */
    static final String NAME_PATTERN = "[A-Za-z0-9._-]+"; //$NON-NLS-1$

    @Inject
    private DbUserDao dbUserDao;

    @Inject
    private SessionDataContainer sessionDataContainer;

    @Inject
    private AuditLogDirector auditLogDirector;

    public UpdateLocalGroupMembersCommand(UpdateLocalGroupMembersParameters parameters, CommandContext context) {
        super(parameters, context);
    }

    @Override
    protected boolean validate() {
        String group = value(getParameters().getGroupName()).trim();
        addCustomValue("TargetGroup", group); //$NON-NLS-1$
        if (group.isEmpty()) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_LOCAL_GROUP_NAME_REQUIRED);
        }
        if (!group.matches(NAME_PATTERN)) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_LOCAL_GROUP_NAME_INVALID);
        }
        if (getParameters().getUsersToAdd().isEmpty() && getParameters().getUsersToRemove().isEmpty()) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_LOCAL_GROUP_MEMBERS_NOT_GIVEN);
        }
        for (String user : allUsers()) {
            if (!value(user).trim().matches(NAME_PATTERN)) {
                return failValidation(EngineMessage.ACTION_TYPE_FAILED_LOCAL_GROUP_MEMBER_NAME_INVALID);
            }
        }
        return true;
    }

    @Override
    protected void executeCommand() {
        String group = getParameters().getGroupName().trim();
        String operator = getCurrentUser() == null ? "unknown" : getCurrentUser().getLoginName(); //$NON-NLS-1$
        Set<String> changed = new LinkedHashSet<>();
        int failed = 0;
        for (String user : trimmed(getParameters().getUsersToAdd())) {
            if (change("useradd", group, user, operator)) { //$NON-NLS-1$
                changed.add(user);
            } else {
                failed++;
            }
        }
        for (String user : trimmed(getParameters().getUsersToRemove())) {
            if (change("userdel", group, user, operator)) { //$NON-NLS-1$
                changed.add(user);
            } else {
                failed++;
            }
        }
        for (String user : changed) {
            endSessionsOf(user, group, operator);
        }
        setActionReturnValue(changed.size());
        // Succeeded when every change was made; the ones that were not are each in the audit log
        // and in what the caller is told.
        setSucceeded(failed == 0);
    }

    /** Runs one change and records it. @return whether it was made */
    private boolean change(String operation, String group, String user, String operator) {
        boolean add = "useradd".equals(operation); //$NON-NLS-1$
        String output;
        boolean made;
        try {
            CommandResult result = run("group-manage", operation, group, "--user=" + user); //$NON-NLS-1$ //$NON-NLS-2$
            made = result.exitCode == 0;
            output = result.output;
        } catch (Exception e) {
            made = false;
            output = e.getMessage();
        }
        if (made) {
            log.info("그룹 구성원 {} 정상; group='{}'; user='{}'; operator='{}'",
                    add ? "추가" : "삭제", group, user, operator); //$NON-NLS-1$ //$NON-NLS-2$
        } else {
            log.error("그룹 구성원 {} 실패; group='{}'; user='{}'; operator='{}'; output='{}'",
                    add ? "추가" : "삭제", group, user, operator, output); //$NON-NLS-1$ //$NON-NLS-2$
            getReturnValue().getExecuteFailedMessages().add(user + ": " + value(output)); //$NON-NLS-1$
        }
        AuditLogType type = add
                ? made ? AuditLogType.LOCAL_GROUP_MEMBER_ADDED : AuditLogType.LOCAL_GROUP_MEMBER_ADD_FAILED
                : made ? AuditLogType.LOCAL_GROUP_MEMBER_REMOVED : AuditLogType.LOCAL_GROUP_MEMBER_REMOVE_FAILED;
        record(event(group, user, operator), type);
        return made;
    }

    /**
     * Ends the sessions the user has open, so that the next login reads the groups as they are now.
     */
    private void endSessionsOf(String userName, String group, String operator) {
        DbUser user = findUser(userName);
        if (user == null) {
            // Never logged in, so no session to end.
            return;
        }
        List<String> sessions = sessionsOf(user);
        if (sessions.isEmpty()) {
            return;
        }
        for (String sessionId : sessions) {
            endSession(sessionId);
        }
        log.info("그룹 구성원 변경으로 세션 종료; group='{}'; user='{}'; sessions={}; operator='{}'",
                group, userName, sessions.size(), operator);
        AuditLogable event = event(group, userName, operator);
        event.addCustomValue("SessionCount", String.valueOf(sessions.size())); //$NON-NLS-1$
        record(event, AuditLogType.LOCAL_GROUP_MEMBER_SESSIONS_TERMINATED);
    }

    private AuditLogable event(String group, String user, String operator) {
        AuditLogable event = new AuditLogableImpl();
        event.setUserName(operator);
        event.addCustomValue("TargetGroup", group); //$NON-NLS-1$
        event.addCustomValue("TargetUser", user); //$NON-NLS-1$
        return event;
    }

    /** Overridable so that a test can see what is recorded. */
    protected void record(AuditLogable event, AuditLogType type) {
        auditLogDirector.log(event, type);
    }

    /** Overridable so that a test can exercise the command without the injected DAO. */
    protected DbUser findUser(String userName) {
        return dbUserDao.getByUsernameAndDomain(userName, INTERNAL_AUTHZ);
    }

    /** Overridable so that a test can exercise the command without the session container. */
    protected List<String> sessionsOf(DbUser user) {
        return sessionDataContainer.getValidSessionIdsOfUser(user.getId());
    }

    /** As an administrator ending a session does (TerminateSessionCommand). */
    protected void endSession(String sessionId) {
        sessionDataContainer.setSessionEndReason(sessionId, SessionEndReason.TERMINATED_BY_ADMIN);
        backend.logoff(new ActionParametersBase(sessionId));
    }

    protected CommandResult run(String... arguments) throws Exception {
        String[] command = new String[arguments.length + 1];
        command[0] = "ovirt-aaa-jdbc-tool"; //$NON-NLS-1$
        System.arraycopy(arguments, 0, command, 1, arguments.length);
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append('\n');
            }
        }
        return new CommandResult(process.waitFor(), output.toString().trim());
    }

    private Set<String> allUsers() {
        Set<String> users = new LinkedHashSet<>(getParameters().getUsersToAdd());
        users.addAll(getParameters().getUsersToRemove());
        return users;
    }

    private static Set<String> trimmed(List<String> users) {
        Set<String> result = new LinkedHashSet<>();
        for (String user : users) {
            result.add(user.trim());
        }
        return result;
    }

    private static String value(String text) {
        return text == null ? "" : text; //$NON-NLS-1$
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        // Every change is recorded on its own, with the user it was about.
        return AuditLogType.UNASSIGNED;
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
