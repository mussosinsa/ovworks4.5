package org.ovirt.engine.ui.webadmin.section.main.presenter.tab;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

/**
 * Which buttons the user list offers, read from the source.
 *
 * <p>The widget calls {@code GWT.create} on the way up, so it cannot be built here; the source
 * is read instead. The point is not to test the framework but to hold a decision that an
 * upstream merge would otherwise undo quietly, in a screen where the undoing is a button that
 * creates accounts.</p>
 */
class UserActionPanelButtonsTest {

    private static final Path SOURCE = Paths.get(
            "src/main/java/org/ovirt/engine/ui/webadmin/section/main/presenter/tab", //$NON-NLS-1$
            "UserActionPanelPresenterWidget.java"); //$NON-NLS-1$

    private static String source() throws IOException {
        assertTrue(Files.isReadable(SOURCE),
                "expected to read " + SOURCE.toAbsolutePath() //$NON-NLS-1$
                        + " from the module directory"); //$NON-NLS-1$
        return new String(Files.readAllBytes(SOURCE), StandardCharsets.UTF_8);
    }

    @Test
    void offersNoWayToPullAccountsInFromADirectoryServer() throws IOException {
        // Accounts on this installation are created and held here. A button that offers to
        // import them from a directory invites an account nobody on this side authorised.
        assertFalse(source().contains("getImportDirectoryElementCommand"), source()); //$NON-NLS-1$
    }

    @Test
    void stillOffersTheThingsTheScreenIsFor() throws IOException {
        String source = source();

        for (String command : new String[] {
            "getAddCommand", //$NON-NLS-1$
            "getEditCommand", //$NON-NLS-1$
            "getRemoveCommand", //$NON-NLS-1$
            "getUnlockUserCommand", //$NON-NLS-1$
            "getResetPasswordCommand", //$NON-NLS-1$
            "getAssignTagsCommand", //$NON-NLS-1$
        }) {
            assertTrue(source.contains(command), command);
        }
    }
}
