package org.ovirt.engine.core.sso.servlets;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.sso.api.AuthenticationException;
import org.ovirt.engine.core.sso.api.SsoConstants;

class InteractiveAuthServletTest {

    @Test
    void expectedAuthenticationFailureUsesGenericLoginMessage() {
        AuthenticationException exception = new AuthenticationException(
                SsoConstants.APP_ERROR_INVALID_CREDENTIALS,
                "sensitive authentication detail"); //$NON-NLS-1$

        assertEquals(SsoConstants.APP_ERROR_AUTHENTICATION_FAILED,
                InteractiveAuthServlet.getSafeLoginMessageCode(exception));
    }

    @Test
    void providerFailureStillRequestsAdministratorIntervention() {
        AuthenticationException exception = new AuthenticationException(
                SsoConstants.APP_ERROR_AUTHENTICATION_FAILED,
                "provider failed", //$NON-NLS-1$
                new IllegalStateException("sensitive provider detail")); //$NON-NLS-1$

        assertEquals(SsoConstants.APP_ERROR_CONTACT_ADMINISTRATOR,
                InteractiveAuthServlet.getSafeLoginMessageCode(exception));
    }

    @Test
    void unexpectedFailureStillRequestsAdministratorIntervention() {
        assertEquals(SsoConstants.APP_ERROR_CONTACT_ADMINISTRATOR,
                InteractiveAuthServlet.getSafeLoginMessageCode(new IllegalStateException("unexpected"))); //$NON-NLS-1$
    }
}
