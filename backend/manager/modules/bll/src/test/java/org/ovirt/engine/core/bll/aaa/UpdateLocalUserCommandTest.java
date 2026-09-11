package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

class UpdateLocalUserCommandTest {

    @Test
    void buildsLocalAaaUserEditArguments() {
        assertArrayEquals(
                new String[] {
                        "user", "edit", "user01", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                        "--attribute=firstName=First", //$NON-NLS-1$
                        "--attribute=lastName=Last", //$NON-NLS-1$
                        "--attribute=email=user01@example.com" //$NON-NLS-1$
                },
                UpdateLocalUserCommand.userEditArguments(
                        "user01", " First ", " Last ", " user01@example.com ")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
    }
}
