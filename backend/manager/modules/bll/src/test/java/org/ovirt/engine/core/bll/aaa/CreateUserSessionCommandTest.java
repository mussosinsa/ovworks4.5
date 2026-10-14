package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;

class CreateUserSessionCommandTest {

    // --- dedicated login IP enforcement ---

    @Test
    void aMatchingDedicatedIpIsAllowed() {
        assertFalse(CreateUserSessionCommand.isLoginDenied(true, false, "10.0.0.5", "10.0.0.5"));
        assertFalse(CreateUserSessionCommand.isLoginDenied(true, true, "10.0.0.5", " 10.0.0.5 "));
    }

    @Test
    void aMismatchedDedicatedIpIsDenied() {
        assertTrue(CreateUserSessionCommand.isLoginDenied(true, false, "10.0.0.5", "10.0.0.6"));
        // A registered address is enforced even for a super user.
        assertTrue(CreateUserSessionCommand.isLoginDenied(true, true, "10.0.0.5", "10.0.0.6"));
    }

    @Test
    void aNonAdminInternalUserWithoutADedicatedIpIsDenied() {
        assertTrue(CreateUserSessionCommand.isLoginDenied(true, false, null, "10.0.0.5"));
        assertTrue(CreateUserSessionCommand.isLoginDenied(true, false, "   ", "10.0.0.5"));
    }

    @Test
    void aSuperUserWithoutADedicatedIpIsAllowedSoAdminsAreNotLockedOut() {
        assertFalse(CreateUserSessionCommand.isLoginDenied(true, true, null, "10.0.0.5"));
    }

    @Test
    void anExternalUserIsNeverRestricted() {
        assertFalse(CreateUserSessionCommand.isLoginDenied(false, false, null, "10.0.0.5"));
        assertFalse(CreateUserSessionCommand.isLoginDenied(false, false, "10.0.0.5", "10.0.0.6"));
    }

    @Test
    void userSessionLimitOverridesEngineDefault() {
        assertEquals(3, CreateUserSessionCommand.resolveSessionLimit(sessionLimit("3"), 1)); //$NON-NLS-1$
    }

    @Test
    void missingOrInvalidUserSessionLimitUsesEngineDefault() {
        assertEquals(2, CreateUserSessionCommand.resolveSessionLimit(null, 2));
        assertEquals(2, CreateUserSessionCommand.resolveSessionLimit(sessionLimit("invalid"), 2)); //$NON-NLS-1$
        assertEquals(2, CreateUserSessionCommand.resolveSessionLimit(sessionLimit("0"), 2)); //$NON-NLS-1$
    }

    private UserProfileProperty sessionLimit(String content) {
        return UserProfileProperty.builder()
                .withName("CONCURRENT_SESSION_LIMIT") //$NON-NLS-1$
                .withTypeJson()
                .withContent(content)
                .build();
    }
}
