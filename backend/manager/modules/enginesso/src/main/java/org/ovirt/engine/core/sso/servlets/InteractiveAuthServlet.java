package org.ovirt.engine.core.sso.servlets;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

import javax.servlet.ServletConfig;
import javax.servlet.http.Cookie;
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
import org.ovirt.engine.core.sso.service.LoginFormNonce;
import org.ovirt.engine.core.sso.service.LoginInputAudit;
import org.ovirt.engine.core.sso.service.LoginReplayAudit;
import org.ovirt.engine.core.sso.service.LoginReplayGuard.LoginEnvelopeException;
import org.ovirt.engine.core.sso.service.SsoService;
import org.ovirt.engine.core.sso.utils.LoginEnvelopeCrypto;
import org.ovirt.engine.core.uutils.security.LoginInputPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InteractiveAuthServlet extends HttpServlet {
    private static final long serialVersionUID = -88168919566901736L;
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String PROFILE = "profile";

    private static Logger log = LoggerFactory.getLogger(InteractiveAuthServlet.class);

    private SsoContext ssoContext;

    @Override
    public void init(ServletConfig config) {
        ssoContext = SsoService.getSsoContext(config.getServletContext());
    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) {
        log.debug("Entered InteractiveAuthServlet");
        try {
            String redirectUrl;
            SsoSession ssoSession = SsoService.getSsoSession(request);
            // clean up the sso session id token
            ssoContext.removeSsoSessionById(ssoSession);
            if (StringUtils.isEmpty(ssoSession.getClientId())) {
                redirectUrl = ssoContext.getEngineUrl();
            } else {
                Credentials userCredentials;
                try {
                    userCredentials = getUserCredentials(request);
                } catch (RefusedLoginForm refused) {
                    // A copy of an earlier login, or a form the login page did not issue. It fails
                    // like a wrong password as far as the browser can tell; the audit log is told
                    // what it was. An ID or password the login page would not have taken is told
                    // as such instead, since the user typed it.
                    response.sendRedirect(handleAuthenticationFailure(
                            request,
                            response,
                            ssoSession,
                            refused.credentials,
                            new AuthenticationException(
                                    refused.errorCode,
                                    ssoContext.getLocalizationUtils().localize(
                                            refused.errorCode,
                                            (Locale) request.getAttribute(SsoConstants.LOCALE)))));
                    return;
                }
                if (SsoService.isUserAuthenticated(request)) {
                    log.debug("User is authenticated redirecting to {}",
                            SsoConstants.INTERACTIVE_REDIRECT_TO_MODULE_URI);
                    redirectUrl = request.getContextPath() + SsoConstants.INTERACTIVE_REDIRECT_TO_MODULE_URI;
                } else if (isInitialLoginRequest(userCredentials)) {
                    // The internal authentication sequence enters this servlet with a GET before
                    // the login form has been submitted. Missing credentials are therefore an
                    // initial form request, not a failed authentication attempt.
                    InteractiveRedirectToModuleServlet.prepareInitialLoginForm(ssoSession);
                    redirectUrl = request.getContextPath() + SsoConstants.INTERACTIVE_LOGIN_FORM_URI;
                } else {
                    try {
                        redirectUrl = authenticateUser(request, response, userCredentials);
                    } catch (Exception ex) {
                        redirectUrl = handleAuthenticationFailure(
                                request,
                                response,
                                ssoSession,
                                userCredentials,
                                ex);
                    }
                }
            }
            if (redirectUrl != null) {
                response.sendRedirect(redirectUrl);
            }
        } catch (Exception ex) {
            SsoService.redirectToErrorPage(request, response, ex);
        }
    }

    private String handleAuthenticationFailure(HttpServletRequest request,
            HttpServletResponse response,
            SsoSession ssoSession,
            Credentials userCredentials,
            Exception exception) {
        String profile = userCredentials.getProfile() == null ? "N/A" : userCredentials.getProfile();
        String authzName = ssoContext.getUserAuthzName(ssoSession);
        String userDomainSuffix = StringUtils.isNotBlank(authzName) ? "@" + authzName : "";
        String sourceAddress = StringUtils.defaultIfEmpty(ssoSession.getSourceAddr(), request.getRemoteAddr());
        String errorCode = exception instanceof AuthenticationException
                ? ((AuthenticationException) exception).getErrorCode()
                : SsoConstants.APP_ERROR_AUTHENTICATION_FAILED;
        if (isPasswordChangeRequired(errorCode)) {
            log.info("Password change required for user {} with profile [{}] connecting from '{}'",
                    userCredentials.getUsername() + userDomainSuffix,
                    profile,
                    sourceAddress);
        } else if (isSingleSessionConflict(errorCode)) {
            log.info("New login rejected because user {} with profile [{}] already has an active session",
                    userCredentials.getUsername() + userDomainSuffix,
                    profile);
        } else {
            log.error("Cannot authenticate user {} with profile [{}] connecting from '{}': {}",
                    userCredentials.getUsername() + userDomainSuffix,
                    profile,
                    sourceAddress,
                    exception.getMessage());
            log.debug("Exception", exception);
        }
        ssoSession.setLoginErrorCode(errorCode);
        if (isPasswordChangeRequired(errorCode)) {
            ssoSession.setLoginMessage(""); //$NON-NLS-1$
        } else {
            ssoSession.setLoginMessage(ssoContext.getLocalizationUtils().localize(
                    getSafeLoginMessageCode(exception),
                    (Locale) request.getAttribute(SsoConstants.LOCALE)));
        }
        ssoSession.setReauthenticate(false);
        ssoContext.registerSsoSessionById(SsoService.generateIdToken(), ssoSession);
        if (StringUtils.isNotEmpty(ssoContext.getSsoDefaultProfile())
                && Arrays.stream(request.getCookies()).noneMatch(c -> c.getName().equals("profile"))) {
            Cookie cookie = new Cookie("profile", ssoContext.getSsoDefaultProfile());
            cookie.setSecure("https".equalsIgnoreCase(request.getScheme()));
            response.addCookie(cookie);
        }
        String redirectUrl = getAuthenticationFailureRedirectUrl(
                errorCode,
                request.getContextPath() + SsoConstants.INTERACTIVE_LOGIN_FORM_URI,
                ssoContext.getChangePasswordUrl());
        log.debug("Redirecting after authentication failure to {}", redirectUrl);
        return redirectUrl;
    }

    static String getSafeLoginMessageCode(Exception exception) {
        if (exception instanceof AuthenticationException
                && SsoConstants.APP_ERROR_SINGLE_SESSION_ALREADY_ACTIVE.equals(
                        ((AuthenticationException) exception).getErrorCode())) {
            return SsoConstants.APP_ERROR_SINGLE_SESSION_ALREADY_ACTIVE;
        }
        if (exception instanceof AuthenticationException
                && SsoConstants.APP_ERROR_LOGIN_INPUT_REJECTED.equals(
                        ((AuthenticationException) exception).getErrorCode())) {
            return SsoConstants.APP_ERROR_LOGIN_INPUT_REJECTED;
        }
        if (exception instanceof AuthenticationException && exception.getCause() == null) {
            return SsoConstants.APP_ERROR_AUTHENTICATION_FAILED;
        }
        return SsoConstants.APP_ERROR_CONTACT_ADMINISTRATOR;
    }

    static boolean isInitialLoginRequest(Credentials credentials) {
        return credentials == null;
    }

    static String getAuthenticationFailureRedirectUrl(String errorCode, String loginUrl, String changePasswordUrl) {
        return isPasswordChangeRequired(errorCode) ? changePasswordUrl : loginUrl;
    }

    static boolean isPasswordChangeRequired(String errorCode) {
        return SsoConstants.APP_ERROR_USER_PASSWORD_EXPIRED_CHANGE_URL_PROVIDED.equals(errorCode);
    }

    static boolean isSingleSessionConflict(String errorCode) {
        return SsoConstants.APP_ERROR_SINGLE_SESSION_ALREADY_ACTIVE.equals(errorCode);
    }

    private String authenticateUser(
            HttpServletRequest request,
            HttpServletResponse response,
            Credentials userCredentials) throws AuthenticationException {
        if (userCredentials == null || !SsoService.areCredentialsValid(request, userCredentials, true)) {
            throw new AuthenticationException(
                    SsoConstants.APP_ERROR_INVALID_CREDENTIALS,
                    ssoContext.getLocalizationUtils().localize(
                            SsoConstants.APP_ERROR_INVALID_CREDENTIALS,
                            (Locale) request.getAttribute(SsoConstants.LOCALE)));
        }
        try {
            log.debug("Authenticating user using credentials");
            Cookie cookie = new Cookie("profile", userCredentials.getProfile());
            cookie.setSecure("https".equalsIgnoreCase(request.getScheme()));
            response.addCookie(cookie);
            AuthenticationService.handleCredentials(
                    ssoContext,
                    request,
                    userCredentials);
            return request.getContextPath() + SsoConstants.INTERACTIVE_REDIRECT_TO_MODULE_URI;
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Extension failures must stay in the interactive login flow. Propagating a runtime
            // exception redirects through SsoPostLoginServlet and exposes "server_error: Invoke
            // failed" on the welcome page instead of returning the user to the login form.
            log.error("Authentication provider invocation failed: {}", ex.getClass().getSimpleName());
            log.debug("Authentication provider invocation exception", ex);
            throw new AuthenticationException(
                    SsoConstants.APP_ERROR_AUTHENTICATION_FAILED,
                    ssoContext.getLocalizationUtils().localize(
                            SsoConstants.APP_ERROR_CONTACT_ADMINISTRATOR,
                            (Locale) request.getAttribute(SsoConstants.LOCALE)),
                    ex);
        }
    }

    private Credentials getUserCredentials(HttpServletRequest request) {
        String username = SsoService.getFormParameter(request, USERNAME);
        String password = SsoService.getFormParameter(request, PASSWORD);
        String encryptedUsername = SsoService.getFormParameter(request, "encryptedUsername"); //$NON-NLS-1$
        String encryptedPassword = SsoService.getFormParameter(request, "encryptedPassword"); //$NON-NLS-1$
        String profile = SsoService.getFormParameter(request, PROFILE);
        try {
            if (encryptedUsername != null && !encryptedUsername.isEmpty()) {
                username = LoginEnvelopeCrypto.decryptUsername(encryptedUsername);
            }
            if (StringUtils.isNotEmpty(encryptedPassword) || StringUtils.isNotEmpty(password)) {
                // A submitted login form. The page wraps the password with a nonce it was issued
                // for this rendering; one that is not wrapped, or names a nonce that is not
                // pending, is a copy of an earlier submission or did not come from the page.
                password = LoginFormNonce.unwrap(
                        SsoService.getSsoSession(request),
                        StringUtils.isNotEmpty(encryptedPassword)
                                ? LoginEnvelopeCrypto.decrypt(encryptedPassword)
                                : password);
            }
        } catch (LoginEnvelopeException refusal) {
            LoginReplayAudit.report(ssoContext, request, username, LoginReplayAudit.Channel.LOGIN_PAGE, refusal);
            throw new RefusedLoginForm(new Credentials(username, null, profile,
                    profile != null && ssoContext.getSsoProfiles().contains(profile)),
                    SsoConstants.APP_ERROR_AUTHENTICATION_FAILED);
        } catch (Exception ex) {
            throw new RuntimeException("Unable to decrypt interactive login credentials", ex); //$NON-NLS-1$
        }
        Credentials credentials;
        // The code is invoked from the login screen as well as when the user changes password.
        // If the login form parameters are not present the code has been invoked from change password flow and
        // we extract the credentials from the credentials saved to sso session.
        if (username == null || password == null || profile == null) {
            credentials = SsoService.getSsoSession(request).getTempCredentials();
        } else {
            // Typed into the login page just now. What it would not have taken is refused before
            // any extension sees it; the credentials saved for a password change were checked
            // when they were typed.
            Optional<LoginInputPolicy.Refusal> refusal = LoginInputAudit.check(
                    ssoContext, request, username, password, LoginReplayAudit.Channel.LOGIN_PAGE);
            if (refusal.isPresent()) {
                throw new RefusedLoginForm(
                        new Credentials(
                                LoginInputAudit.recordedUserName(username, refusal.get()),
                                null,
                                profile,
                                ssoContext.getSsoProfiles().contains(profile)),
                        SsoConstants.APP_ERROR_LOGIN_INPUT_REJECTED);
            }
            credentials = new Credentials(username, password, profile, ssoContext.getSsoProfiles().contains(profile));
        }
        return credentials;
    }

    /** A login form submission refused before its credentials were checked. */
    private static final class RefusedLoginForm extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private final transient Credentials credentials;
        private final String errorCode;

        private RefusedLoginForm(Credentials credentials, String errorCode) {
            super(null, null, false, false);
            this.credentials = credentials;
            this.errorCode = errorCode;
        }
    }
}
