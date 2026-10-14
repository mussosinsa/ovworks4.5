package org.ovirt.engine.core.sso.servlets;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.ServletOutputStream;
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
        when(response.getOutputStream()).thenReturn(mock(ServletOutputStream.class));
        OAuthAuthorizeServlet servlet = new OAuthAuthorizeServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void requireRegisteredTerminal(HttpServletRequest request) {
                throw new ClientSerialRejectedException(Refusal.MISSING);
            }
        };

        servlet.service(request, response);

        // The web server's own Forbidden page. Not a 401: this application maps 401 to the next
        // step of the login, which a refused request cannot take ("Internal Server Error").
        verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verify(response).setContentType("text/html; charset=iso-8859-1");
        verify(response, never()).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid client serial.");
        // Refused before the request was read, so no session was started for it.
        verify(request, never()).getSession(true);
        verify(request, never()).getParameter(anyString());
    }
}
