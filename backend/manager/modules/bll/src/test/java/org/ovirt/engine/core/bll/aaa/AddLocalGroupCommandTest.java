package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.common.action.AddLocalGroupParameters;
import org.ovirt.engine.core.common.businessentities.aaa.DbGroup;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.compat.Guid;

class AddLocalGroupCommandTest {
    private static final String ADD = "add"; //$NON-NLS-1$
    private static final String SHOW = "show"; //$NON-NLS-1$
    private static final String PRINCIPAL_ID = "6be45bbc-ad97-11f1-9f56-566f0a1b2c3d"; //$NON-NLS-1$

    /* The name is checked by the engine as well as by the dialog, and every refusal says why. */

    @Test
    void refusesAnEmptyNameAndSaysSo() {
        for (String name : Arrays.asList(null, "", "   ")) { //$NON-NLS-1$ //$NON-NLS-2$
            TestCommand command = new TestCommand(name);

            assertFalse(command.validate());
            assertEquals(Collections.singletonList(EngineMessage.ACTION_TYPE_FAILED_LOCAL_GROUP_NAME_REQUIRED.name()),
                    command.getReturnValue().getValidationMessages());
        }
    }

    @Test
    void refusesANameTheProviderWouldNotAcceptAndSaysSo() {
        for (String name : Arrays.asList("ops team", "ops;rm", "그룹", "a/b", "$(id)")) { //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
            TestCommand command = new TestCommand(name);

            assertFalse(command.validate(), name);
            assertEquals(Collections.singletonList(EngineMessage.ACTION_TYPE_FAILED_LOCAL_GROUP_NAME_INVALID.name()),
                    command.getReturnValue().getValidationMessages(), name);
        }
    }

    @Test
    void acceptsLettersDigitsDotsUnderscoresAndHyphens() {
        for (String name : Arrays.asList("SAEOLL", "team.ops-1", "  ops_2  ")) { //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            TestCommand command = new TestCommand(name);

            assertTrue(command.validate(), name);
            assertTrue(command.getReturnValue().getValidationMessages().isEmpty(), name);
        }
    }

    /* Creating the group. */

    @Test
    void createsTheGroupAndRecordsItUnderTheProvidersIdentifier() {
        TestCommand command = new TestCommand(" SAEOLL "); //$NON-NLS-1$
        command.result(ADD, 0, ""); //$NON-NLS-1$
        command.result(SHOW, 0, "-- Group SAEOLL(" + PRINCIPAL_ID + ") --"); //$NON-NLS-1$ //$NON-NLS-2$

        command.executeCommand();

        assertTrue(command.getReturnValue().getSucceeded());
        // The name the tool is given is the trimmed one.
        assertEquals(Arrays.asList("group", ADD, "SAEOLL"), command.invocations.get(0)); //$NON-NLS-1$ //$NON-NLS-2$
        assertEquals(Arrays.asList(ADD, SHOW), command.operations());
        DbGroup saved = command.saved;
        assertEquals("SAEOLL", saved.getName()); //$NON-NLS-1$
        assertEquals(PRINCIPAL_ID, saved.getExternalId());
        assertEquals("internal-authz", saved.getDomain()); //$NON-NLS-1$
        assertEquals(saved.getId(), command.getReturnValue().getActionReturnValue());
    }

    @Test
    void reportsWhatTheToolSaidWhenItRefusesTheGroup() {
        TestCommand command = new TestCommand("SAEOLL"); //$NON-NLS-1$
        command.result(ADD, 1, "Group SAEOLL already exists"); //$NON-NLS-1$

        command.executeCommand();

        assertFalse(command.getReturnValue().getSucceeded());
        assertEquals(Collections.singletonList("Group SAEOLL already exists"), //$NON-NLS-1$
                command.getReturnValue().getExecuteFailedMessages());
        assertEquals(Collections.singletonList(ADD), command.operations());
        assertNull(command.saved);
    }

    @Test
    void writesNoRowWhenTheProviderGivesNoIdentifier() {
        // A row under a made-up identifier would become a second group that only looks like this
        // one the first time a permission is granted to it.
        TestCommand command = new TestCommand("SAEOLL"); //$NON-NLS-1$
        command.result(ADD, 0, ""); //$NON-NLS-1$
        command.result(SHOW, 0, "Group SAEOLL"); //$NON-NLS-1$

        command.executeCommand();

        assertTrue(command.getReturnValue().getSucceeded());
        assertNull(command.saved);
        assertNull(command.getReturnValue().getActionReturnValue());
    }

    @Test
    void reusesTheEnginesRowWhenItAlreadyHasOne() {
        DbGroup existing = new DbGroup();
        existing.setId(Guid.newGuid());
        existing.setName("SAEOLL"); //$NON-NLS-1$
        TestCommand command = new TestCommand("SAEOLL"); //$NON-NLS-1$
        command.existing = existing;
        command.result(ADD, 0, ""); //$NON-NLS-1$

        command.executeCommand();

        assertTrue(command.getReturnValue().getSucceeded());
        assertEquals(Collections.singletonList(ADD), command.operations());
        assertNull(command.saved);
        assertEquals(existing.getId(), command.getReturnValue().getActionReturnValue());
    }

    @Test
    void reportsAToolThatCannotBeRun() {
        TestCommand command = new TestCommand("SAEOLL"); //$NON-NLS-1$
        command.failure = new java.io.IOException("Cannot run program \"ovirt-aaa-jdbc-tool\""); //$NON-NLS-1$

        command.executeCommand();

        assertFalse(command.getReturnValue().getSucceeded());
        assertTrue(command.getReturnValue().getExecuteFailedMessages().get(0).contains("ovirt-aaa-jdbc-tool")); //$NON-NLS-1$
    }

    private static class TestCommand extends AddLocalGroupCommand {
        private final List<List<String>> invocations = new ArrayList<>();
        private final List<String> resultOperations = new ArrayList<>();
        private final List<CommandResult> results = new ArrayList<>();
        private DbGroup existing;
        private DbGroup saved;
        private Exception failure;

        TestCommand(String groupName) {
            super(new AddLocalGroupParameters(groupName), CommandContext.createContext("")); //$NON-NLS-1$
        }

        void result(String operation, int exitCode, String output) {
            resultOperations.add(operation);
            results.add(new CommandResult(exitCode, output));
        }

        List<String> operations() {
            List<String> operations = new ArrayList<>();
            for (List<String> arguments : invocations) {
                operations.add(arguments.get(1));
            }
            return operations;
        }

        @Override
        protected CommandResult run(String... arguments) throws Exception {
            if (failure != null) {
                throw failure;
            }
            invocations.add(Arrays.asList(arguments));
            int index = resultOperations.indexOf(arguments[1]);
            if (index < 0) {
                throw new AssertionError("unexpected ovirt-aaa-jdbc-tool " + arguments[1]); //$NON-NLS-1$
            }
            return results.get(index);
        }

        @Override
        protected DbGroup findGroup(String groupName) {
            return existing;
        }

        @Override
        protected void saveGroup(DbGroup group) {
            saved = group;
        }
    }
}
