package org.ovirt.engine.core.sso.servlets;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.ovirt.engine.core.sso.api.SsoConstants;
import org.ovirt.engine.core.sso.api.SsoSession;
import org.ovirt.engine.core.sso.service.SsoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InteractiveRedirectToModuleServlet extends HttpServlet {
    private static final long serialVersionUID = -4283642288798438953L;
    private static Logger log = LoggerFactory.getLogger(InteractiveRedirectToModuleServlet.class);

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        if (SsoService.isUserAuthenticated(request)) {
            log.debug("User is authenticated redirecting to module");
            SsoService.redirectToModule(
                    request,
                    response);
        } else {
            prepareInitialLoginForm(SsoService.getSsoSession(request));
            response.sendRedirect(request.getContextPath() + SsoConstants.INTERACTIVE_LOGIN_FORM_URI);
        }
    }

    static void prepareInitialLoginForm(SsoSession ssoSession) {
        // This path opens a new interactive login form; it is not the redirect used after a
        // submitted credential failure. Do not carry a stale error from an earlier SSO flow
        // into the first WebAdmin login screen.
        //
        // A password change that has just succeeded is the exception. It sends the user back here
        // to log in with the new password and leaves word of that on the session, and this is the
        // screen that word was left for - clearing it meant the change reported nothing at all,
        // which on a first login is indistinguishable from having failed.
        if (!SsoConstants.APP_MSG_CHANGE_PASSWORD_SUCCEEDED.equals(ssoSession.getLoginErrorCode())) {
            ssoSession.setLoginMessage(""); //$NON-NLS-1$
            ssoSession.setLoginErrorCode(""); //$NON-NLS-1$
        }
        ssoSession.setReauthenticate(false);
    }
}
