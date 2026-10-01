package org.ovirt.engine.core.sso.servlets;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.sso.api.ClientSerialRejectedException;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck.Refusal;

class OAuthAuthorizeServletTest {

    @Test
    void aLoginStartedWithoutATerminalIsTurnedAwayBeforeAnythingElse() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        OAuthAuthorizeServlet servlet = new OAuthAuthorizeServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void requireRegisteredTerminal(HttpServletRequest request) {
                throw new ClientSerialRejectedException(Refusal.MISSING);
            }
        };

        servlet.service(request, response);

        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid client serial.");
        // Refused before the request was read, so no session was started for it.
        verify(request, never()).getSession(true);
        verify(request, never()).getParameter(anyString());
    }
}
