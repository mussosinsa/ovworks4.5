package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.action.UpdateLocalGroupMembersParameters;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;

/**
 * A group's members are changed through the provider's own tool, one user at a time; every change
 * is recorded on its own, and the users whose membership changed have their sessions ended so that
 * the change takes effect at once.
 */
class UpdateLocalGroupMembersCommandTest {

    @Test
    void refusesWhatTheToolWouldNotAcceptAndSaysWhy() {
        assertRefused(new TestCommand("", List.of("u1"), List.of()),
                EngineMessage.ACTION_TYPE_FAILED_LOCAL_GROUP_NAME_REQUIRED);
        assertRefused(new TestCommand("ops team", List.of("u1"), List.of()),
                EngineMessage.ACTION_TYPE_FAILED_LOCAL_GROUP_NAME_INVALID);
        assertRefused(new TestCommand("ops", List.of(), List.of()),
                EngineMessage.ACTION_TYPE_FAILED_LOCAL_GROUP_MEMBERS_NOT_GIVEN);
        assertRefused(new TestCommand("ops", List.of("u1;rm -rf"), List.of()),
                EngineMessage.ACTION_TYPE_FAILED_LOCAL_GROUP_MEMBER_NAME_INVALID);
        assertRefused(new TestCommand("ops", List.of(), List.of("--user=x y")),
                EngineMessage.ACTION_TYPE_FAILED_LOCAL_GROUP_MEMBER_NAME_INVALID);
        assertTrue(new TestCommand("ops", List.of("user01"), List.of("user.02")).validate());
    }

    @Test
    void addsAndRemovesEachUserWithTheTool() {
        TestCommand command = new TestCommand("ops", List.of("user01", "user02"), List.of("user03"));
        command.executeCommand();

        assertEquals(Arrays.asList(
                Arrays.asList("group-manage", "useradd", "ops", "--user=user01"),
                Arrays.asList("group-manage", "useradd", "ops", "--user=user02"),
                Arrays.asList("group-manage", "userdel", "ops", "--user=user03")), command.invocations);
        assertTrue(command.getReturnValue().getSucceeded());
        assertEquals(Arrays.asList(AuditLogType.LOCAL_GROUP_MEMBER_ADDED, AuditLogType.LOCAL_GROUP_MEMBER_ADDED,
                AuditLogType.LOCAL_GROUP_MEMBER_REMOVED), command.types());
        assertEquals("user03", command.recorded.get(2).getCustomValues().get("targetuser"));
        assertEquals("ops", command.recorded.get(2).getCustomValues().get("targetgroup"));
    }

    @Test
    void endsTheSessionsOfEveryUserWhoseMembershipChanged() {
        TestCommand command = new TestCommand("ops", List.of("user01"), List.of("user02"));
        command.sessions.put("user01", List.of("s1", "s2"));
        command.sessions.put("user02", List.of("s3"));
        command.sessions.put("bystander", List.of("s9"));
        command.executeCommand();

        assertEquals(new HashSet<>(Arrays.asList("s1", "s2", "s3")), command.ended);
        assertEquals(2, Collections.frequency(command.types(), AuditLogType.LOCAL_GROUP_MEMBER_SESSIONS_TERMINATED));
    }

    @Test
    void aChangeTheToolRefusesIsRecordedAndItsSessionsAreLeftAlone() {
        TestCommand command = new TestCommand("ops", List.of("user01", "ghost"), List.of());
        command.refused.add("ghost");
        command.sessions.put("ghost", List.of("s7"));
        command.executeCommand();

        assertFalse(command.getReturnValue().getSucceeded());
        assertEquals(Arrays.asList(AuditLogType.LOCAL_GROUP_MEMBER_ADDED, AuditLogType.LOCAL_GROUP_MEMBER_ADD_FAILED),
                command.types());
        assertTrue(command.ended.isEmpty());
        assertTrue(command.getReturnValue().getExecuteFailedMessages().get(0).startsWith("ghost: "));
    }

    private static void assertRefused(TestCommand command, EngineMessage message) {
        assertFalse(command.validate());
        assertEquals(Collections.singletonList(message.name()), command.getReturnValue().getValidationMessages());
    }

    private static class TestCommand extends UpdateLocalGroupMembersCommand {
        private final List<List<String>> invocations = new ArrayList<>();
        private final List<AuditLogable> recorded = new ArrayList<>();
        private final List<AuditLogType> recordedTypes = new ArrayList<>();
        private final Set<String> refused = new HashSet<>();
        private final Map<String, List<String>> sessions = new HashMap<>();
        private final Map<Guid, String> userNames = new HashMap<>();
        private final Set<String> ended = new HashSet<>();

        TestCommand(String group, List<String> add, List<String> remove) {
            super(new UpdateLocalGroupMembersParameters(group, add, remove), CommandContext.createContext("")); //$NON-NLS-1$
        }

        List<AuditLogType> types() {
            List<AuditLogType> types = new ArrayList<>(recordedTypes);
            types.removeIf(type -> type == AuditLogType.LOCAL_GROUP_MEMBER_SESSIONS_TERMINATED
                    && !recordedTypes.isEmpty() && sessions.isEmpty());
            return types;
        }

        @Override
        protected CommandResult run(String... arguments) {
            invocations.add(Arrays.asList(arguments));
            String user = arguments[3].substring("--user=".length());
            return refused.contains(user)
                    ? new CommandResult(1, "User not found")
                    : new CommandResult(0, "");
        }

        @Override
        protected void record(AuditLogable event, AuditLogType type) {
            recorded.add(event);
            recordedTypes.add(type);
        }

        @Override
        protected DbUser findUser(String userName) {
            DbUser user = new DbUser();
            user.setId(Guid.newGuid());
            user.setLoginName(userName);
            userNames.put(user.getId(), userName);
            return user;
        }

        @Override
        protected List<String> sessionsOf(DbUser user) {
            return sessions.getOrDefault(userNames.get(user.getId()), List.of());
        }

        @Override
        protected void endSession(String sessionId) {
            ended.add(sessionId);
        }
    }
}
