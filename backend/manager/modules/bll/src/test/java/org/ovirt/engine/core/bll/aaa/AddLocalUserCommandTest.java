package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.common.action.AddLocalUserParameters;

class AddLocalUserCommandTest {
    private static final DateTimeFormatter PASSWORD_VALID_TO_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssX"); //$NON-NLS-1$
    private static final String ADD = "add"; //$NON-NLS-1$
    private static final String PASSWORD_RESET = "password-reset"; //$NON-NLS-1$
    private static final String DELETE = "delete"; //$NON-NLS-1$

    @Test
    void removesNewAaaUserWhenPasswordInitializationFails() {
        TestCommand command = new TestCommand(0, 1, 0);

        command.executeCommand();

        assertFalse(command.getReturnValue().getSucceeded());
        assertEquals(Arrays.asList(ADD, PASSWORD_RESET, DELETE), command.operations);
    }

    @Test
    void doesNotDeleteUserWhenCreationItselfFails() {
        TestCommand command = new TestCommand(1);

        command.executeCommand();

        assertFalse(command.getReturnValue().getSucceeded());
        assertEquals(Arrays.asList(ADD), command.operations);
    }

    @Test
    void reportsRollbackFailureWithoutReplacingOriginalFailure() {
        TestCommand command = new TestCommand(0, 1, 2);

        command.executeCommand();

        assertFalse(command.getReturnValue().getSucceeded());
        assertEquals(2, command.getReturnValue().getExecuteFailedMessages().size());
        assertEquals(Arrays.asList(ADD, PASSWORD_RESET, DELETE), command.operations);
    }

    @Test
    void initialPasswordExpiresImmediately() {
        ZonedDateTime validTo = ZonedDateTime.parse(
                AddLocalUserCommand.initialPasswordValidTo(), PASSWORD_VALID_TO_FORMAT);

        assertFalse(validTo.isAfter(ZonedDateTime.now()));
    }

    private static class TestCommand extends AddLocalUserCommand {
        private final List<Integer> exitCodes;
        private final List<String> operations = new ArrayList<>();
        private int invocation;

        TestCommand(Integer... exitCodes) {
            super(new AddLocalUserParameters("new-user", "New", "User", "Secret123!", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
                            "2030-01-01 00:00:00Z"), //$NON-NLS-1$
                    CommandContext.createContext("")); //$NON-NLS-1$
            this.exitCodes = Arrays.asList(exitCodes);
        }

        @Override
        protected CommandResult run(String... arguments) {
            operations.add(arguments[1]);
            int exitCode = exitCodes.get(invocation++);
            return new CommandResult(exitCode, exitCode == 0 ? "" : "simulated failure"); //$NON-NLS-1$ //$NON-NLS-2$
        }
    }
}
