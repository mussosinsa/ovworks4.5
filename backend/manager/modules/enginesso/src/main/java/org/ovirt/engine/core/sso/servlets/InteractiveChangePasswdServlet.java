package org.ovirt.engine.core.sso.servlets;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.sso.api.AuthenticationException;
import org.ovirt.engine.core.sso.api.Credentials;
import org.ovirt.engine.core.sso.api.SsoConstants;
import org.ovirt.engine.core.sso.api.SsoContext;
import org.ovirt.engine.core.sso.api.SsoSession;
import org.ovirt.engine.core.sso.service.AuthenticationService;
import org.ovirt.engine.core.sso.service.PasswordPolicyService;
import org.ovirt.engine.core.sso.service.SsoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InteractiveChangePasswdServlet extends HttpServlet {

    private static final long serialVersionUID = -88168919566901736L;
    private static final String USERNAME = "username";
    private static final String CREDENTIALS = "credentials";
    private static final String CREDENTIALS_NEW1 = "credentialsNew1";
    private static final String CREDENTIALS_NEW2 = "credentialsNew2";
    private static final String PROFILE = "profile";

    private static Logger log = LoggerFactory.getLogger(InteractiveChangePasswdServlet.class);

    private SsoContext ssoContext;

    @Override
    public void init(ServletConfig config) throws ServletException {
        ssoContext = SsoService.getSsoContext(config.getServletContext());
    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        log.debug("Entered InteractiveChangePasswdServlet");
        Credentials userCredentials = null;
        String redirectUrl;
        try {
            log.debug("User is not authenticated extracting credentials from request.");
            userCredentials = getUserCredentials(request);
            if (userCredentials == null) {
                throw new AuthenticationException(
                        SsoConstants.APP_ERROR_UNABLE_TO_EXTRACT_CREDENTIALS,
                        ssoContext.getLocalizationUtils().localize(
                                SsoConstants.APP_ERROR_UNABLE_TO_EXTRACT_CREDENTIALS,
                                (Locale) request.getAttribute(SsoConstants.LOCALE)));
            }
            if (!userCredentials.getNewCredentials().equals(userCredentials.getConfirmedNewCredentials())) {
                throw new AuthenticationException(
                        SsoConstants.APP_ERROR_PASSWORDS_DONT_MATCH,
                        ssoContext.getLocalizationUtils().localize(
                                SsoConstants.APP_ERROR_PASSWORDS_DONT_MATCH,
                                (Locale) request.getAttribute(SsoConstants.LOCALE)));
            }
            // The engine password policy is enforced here rather than being left to whatever
            // the authn extension happens to be configured with. This is the code path a user
            // is sent through when the password is expired, i.e. on the first login after the
            // password was set by an administrator or by engine-setup.
            List<String> policyViolations = PasswordPolicyService.validate(ssoContext, userCredentials);
            if (!policyViolations.isEmpty()) {
                throw new AuthenticationException(
                        SsoConstants.APP_ERROR_PASSWORD_POLICY_VIOLATION,
                        String.join(" ", policyViolations));
            }
            redirectUrl = changeUserPasswd(request, userCredentials);
        } catch (Exception ex) {
            String auditMsg = String.format(
                    "Password change failed for user '%s': %s", //$NON-NLS-1$
                    userCredentials == null ? "" : userCredentials.getUsernameWithProfile(),
                    ex.getMessage());
            log.error(auditMsg);
            log.debug("Exception", ex);
            notifyPasswordChangeEvent(userCredentials, false);
            SsoService.getSsoSession(request).setChangePasswdMessage(
                    ssoContext.getLocalizationUtils().localize(
                            SsoConstants.APP_ERROR_CONTACT_ADMINISTRATOR,
                            (Locale) request.getAttribute(SsoConstants.LOCALE)));
            redirectUrl = SsoService.getSsoContext(request).getChangePasswordUrl();
        }
        log.debug("Redirecting to url: {}", redirectUrl);
        response.sendRedirect(redirectUrl);
    }

    private String changeUserPasswd(HttpServletRequest request, Credentials userCredentials)
            throws AuthenticationException {
        log.debug("Calling Authn to change password for user '{}'.",
                userCredentials.getUsernameWithProfile());
        AuthenticationService.changePassword(ssoContext, request, userCredentials);
        PasswordPolicyService.recordPasswordHistory(ssoContext, userCredentials);
        SsoSession ssoSession = SsoService.getSsoSession(request);
        ssoSession.setChangePasswdCredentials(null);
        if (SsoService.isUserAuthenticated(request)) {
            log.debug("User is authenticated updating password in SsoSession for password-access scope.");
            SsoService.persistUserPassword(request, ssoSession, userCredentials.getNewCredentials());
        } else {
            log.debug("User password change succeeded, redirecting to login page.");
            ssoSession.setLoginErrorCode(SsoConstants.APP_MSG_CHANGE_PASSWORD_SUCCEEDED);
            ssoSession.setLoginMessage(
                ssoContext.getLocalizationUtils().localize(
                        SsoConstants.APP_MSG_CHANGE_PASSWORD_SUCCEEDED,
                        (Locale) request.getAttribute(SsoConstants.LOCALE)));
        }
        notifyPasswordChangeEvent(userCredentials, true);
        return request.getContextPath() + SsoConstants.INTERACTIVE_LOGIN_URI;
    }

    private void notifyPasswordChangeEvent(Credentials credentials, boolean succeeded) {
        if (credentials == null) {
            return;
        }
        try {
            SsoService.notifyClientOfPasswordChangeEvent(
                    ssoContext,
                    ssoContext.getSsoLocalConfig().getProperty("ENGINE_SSO_CLIENT_ID"),
                    credentials.getUsernameWithProfile(),
                    succeeded);
        } catch (Exception exception) {
            // Audit delivery must not change the result of a credential change.
            log.error("Unable to report password change event for user '{}'",
                    credentials.getUsernameWithProfile(), exception);
        }
    }

    private Credentials getUserCredentials(HttpServletRequest request) throws AuthenticationException {
        try {
            String username = SsoService.getFormParameter(request, USERNAME);
            String credentials = SsoService.getFormParameter(request, CREDENTIALS);
            String credentialsNew1 = SsoService.getFormParameter(request, CREDENTIALS_NEW1);
            String credentialsNew2 = SsoService.getFormParameter(request, CREDENTIALS_NEW2);
            String profile = SsoService.getFormParameter(request, PROFILE);
            return StringUtils.isNotEmpty(username) &&
                    StringUtils.isNotEmpty(credentials) &&
                    StringUtils.isNotEmpty(credentialsNew1) &&
                    StringUtils.isNotEmpty(credentialsNew2) &&
                    StringUtils.isNotEmpty(profile)
                            ? new Credentials(username, credentials, credentialsNew1, credentialsNew2, profile)
                            : null;
        } catch (Exception ex) {
            throw new AuthenticationException(
                    SsoConstants.APP_ERROR_UNABLE_TO_EXTRACT_CREDENTIALS,
                    ssoContext.getLocalizationUtils().localize(
                            SsoConstants.APP_ERROR_UNABLE_TO_EXTRACT_CREDENTIALS,
                            (Locale) request.getAttribute(SsoConstants.LOCALE)),
                    ex);
        }
    }

}
