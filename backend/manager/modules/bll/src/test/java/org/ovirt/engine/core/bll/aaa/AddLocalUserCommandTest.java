package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.common.action.AddLocalUserParameters;

class AddLocalUserCommandTest {
    private static final String ADD = "add"; //$NON-NLS-1$
    private static final String PASSWORD_RESET = "password-reset"; //$NON-NLS-1$
    private static final String DELETE = "delete"; //$NON-NLS-1$
    private static final String VALID_TO_ARGUMENT = "--password-valid-to="; //$NON-NLS-1$

    /** The switch that tells ovirt-aaa-jdbc-tool the caller has already decided the policy. */
    private static final String ENGINE_POLICY_IS_AUTHORITATIVE = "--force"; //$NON-NLS-1$

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
    void initialPasswordIsAlreadyExpiredWhenTheFirstLoginChangeIsRequired() {
        ZonedDateTime validTo =
                InitialPasswordValidity.parse(AddLocalUserCommand.initialPasswordValidTo(true));

        assertTrue(validTo.isBefore(ZonedDateTime.now()));
    }

    @Test
    void initialPasswordIsUsableWhenTheFirstLoginChangeIsNotRequired() {
        // Creating a user answers to PasswordPolicyForceChangeOnFirstLogin just as resetting a
        // password does. It used to expire the password whatever the setting said, which left the
        // user in the credential-change flow on a deployment that had turned the policy off.
        ZonedDateTime validTo =
                InitialPasswordValidity.parse(AddLocalUserCommand.initialPasswordValidTo(false));

        assertTrue(validTo.isAfter(ZonedDateTime.now()));
    }

    // The password reset is made to fail in both of these so the command stops before the steps
    // that need the injected DAOs. The argument under test is passed to the tool either way.

    @Test
    void expiresTheAssignedPasswordWhenThePolicyRequiresAFirstLoginChange() {
        TestCommand command = new TestCommand(true, 0, 1, 0);

        command.executeCommand();

        assertTrue(command.passwordValidTo().isBefore(ZonedDateTime.now()));
    }

    @Test
    void leavesTheAssignedPasswordUsableWhenThePolicyDoesNot() {
        TestCommand command = new TestCommand(false, 0, 1, 0);

        command.executeCommand();

        assertTrue(command.passwordValidTo().isAfter(ZonedDateTime.now()));
    }

    @Test
    void leavesThePasswordRulesToTheEngineWhenAssigningTheInitialPassword() {
        TestCommand command = new TestCommand(0, 1, 0);

        command.executeCommand();

        // The engine has already run its own policy in validatePasswordPolicy(). The tool's is a
        // different set - among other things it counts only a fixed list of ASCII punctuation as
        // a special character - so leaving it on refuses passwords the dialog accepted, and the
        // account created a moment earlier is rolled back.
        assertTrue(command.argumentsOf(PASSWORD_RESET).contains(ENGINE_POLICY_IS_AUTHORITATIVE));
    }

    @Test
    void doesNotPassThatAnywhereItWouldNotMeanTheSameThing() {
        TestCommand command = new TestCommand(0, 1, 0);

        command.executeCommand();

        assertFalse(command.argumentsOf(ADD).contains(ENGINE_POLICY_IS_AUTHORITATIVE));
        assertFalse(command.argumentsOf(DELETE).contains(ENGINE_POLICY_IS_AUTHORITATIVE));
    }

    /* Reading the identifier the authorization provider gave the account */

    @Test
    void readsThePrincipalIdentifierFromItsOwnField() {
        String output = "-- User new-user --\n" //$NON-NLS-1$
                + "Namespace: *\n" //$NON-NLS-1$
                + "Name: new-user\n" //$NON-NLS-1$
                + "ID: 6be45bbc-ad97-11f1-9f56-566f0a1b2c3d\n" //$NON-NLS-1$
                + "Display Name:\n"; //$NON-NLS-1$

        assertEquals("6be45bbc-ad97-11f1-9f56-566f0a1b2c3d", //$NON-NLS-1$
                AaaJdbcTool.principalIdOf(output));
    }

    @Test
    void readsThePrincipalIdentifierFromTheHeadingWhenThereIsNoFieldForIt() {
        String output = "-- User new-user(6be45bbc-ad97-11f1-9f56-566f0a1b2c3d) --\n" //$NON-NLS-1$
                + "Namespace: *\n" //$NON-NLS-1$
                + "Name: new-user\n"; //$NON-NLS-1$

        assertEquals("6be45bbc-ad97-11f1-9f56-566f0a1b2c3d", //$NON-NLS-1$
                AaaJdbcTool.principalIdOf(output));
    }

    @Test
    void answersWithNothingWhenTheOutputCarriesNoIdentifier() {
        // The tool having changed under us. Reported by the caller and no row written, because a
        // row filed under the wrong identifier is what this exists to stop.
        assertNull(AaaJdbcTool.principalIdOf("-- User new-user --\nName: new-user\n")); //$NON-NLS-1$
        assertNull(AaaJdbcTool.principalIdOf("")); //$NON-NLS-1$
        assertNull(AaaJdbcTool.principalIdOf(null));
    }

    private static class TestCommand extends AddLocalUserCommand {
        private final List<Integer> exitCodes;
        private final List<String> operations = new ArrayList<>();
        private final List<String[]> invocations = new ArrayList<>();
        private final boolean forceChangeOnFirstLogin;
        private int invocation;

        TestCommand(Integer... exitCodes) {
            this(false, exitCodes);
        }

        TestCommand(boolean forceChangeOnFirstLogin, Integer... exitCodes) {
            super(new AddLocalUserParameters("new-user", "New", "User", "Secret123!", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
                            "2030-01-01 00:00:00Z"), //$NON-NLS-1$
                    CommandContext.createContext("")); //$NON-NLS-1$
            this.exitCodes = Arrays.asList(exitCodes);
            this.forceChangeOnFirstLogin = forceChangeOnFirstLogin;
        }

        @Override
        protected boolean isForceChangeOnFirstLogin() {
            return forceChangeOnFirstLogin;
        }

        @Override
        protected CommandResult run(String... arguments) {
            operations.add(arguments[1]);
            invocations.add(arguments);
            int exitCode = exitCodes.get(invocation++);
            return new CommandResult(exitCode, exitCode == 0 ? "" : "simulated failure"); //$NON-NLS-1$ //$NON-NLS-2$
        }

        /** @return the arguments of the invocation that ran the given ovirt-aaa-jdbc-tool operation */
        List<String> argumentsOf(String operation) {
            for (String[] arguments : invocations) {
                if (operation.equals(arguments[1])) {
                    return Arrays.asList(arguments);
                }
            }
            throw new AssertionError("the command never ran " + operation); //$NON-NLS-1$
        }

        /** The --password-valid-to the command handed to ovirt-aaa-jdbc-tool. */
        ZonedDateTime passwordValidTo() {
            for (String[] arguments : invocations) {
                for (String argument : arguments) {
                    if (argument.startsWith(VALID_TO_ARGUMENT)) {
                        return InitialPasswordValidity.parse(
                                argument.substring(VALID_TO_ARGUMENT.length()));
                    }
                }
            }
            throw new AssertionError("the command never passed " + VALID_TO_ARGUMENT); //$NON-NLS-1$
        }
    }
}
