package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;

class CreateUserSessionCommandTest {

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
