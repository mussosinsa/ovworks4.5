package org.ovirt.engine.core.sso.servlets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.sso.api.SsoSession;

class InteractiveRedirectToModuleServletTest {

    @Test
    void initialLoginDoesNotDisplayAnErrorFromAnEarlierSsoFlow() {
        SsoSession session = new SsoSession();
        session.setLoginMessage("Authentication failed."); //$NON-NLS-1$
        session.setLoginErrorCode("AUTHENTICATION_FAILED"); //$NON-NLS-1$
        session.setReauthenticate(true);

        InteractiveRedirectToModuleServlet.prepareInitialLoginForm(session);

        assertEquals("", session.getLoginMessage()); //$NON-NLS-1$
        assertEquals("", session.getLoginErrorCode()); //$NON-NLS-1$
        assertFalse(session.isReauthenticate());
    }
}
