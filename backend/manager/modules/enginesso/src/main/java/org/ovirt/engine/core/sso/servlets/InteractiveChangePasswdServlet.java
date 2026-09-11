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
import org.ovirt.engine.core.sso.utils.LoginEnvelopeCrypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InteractiveChangePasswdServlet extends HttpServlet {

    private static final long serialVersionUID = -88168919566901736L;
    private static final String USERNAME = "username";
    private static final String CREDENTIALS = "credentials";
    private static final String CREDENTIALS_NEW1 = "credentialsNew1";
    private static final String CREDENTIALS_NEW2 = "credentialsNew2";
    private static final String PROFILE = "profile";
    private static final String ENCRYPTED_CREDENTIALS = "encryptedCredentials";
    private static final String ENCRYPTED_CREDENTIALS_NEW1 = "encryptedCredentialsNew1";
    private static final String ENCRYPTED_CREDENTIALS_NEW2 = "encryptedCredentialsNew2";

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
            SsoService.getSsoSession(request).setChangePasswdMessage(reasonToShow(request, ex));
            redirectUrl = SsoService.getSsoContext(request).getChangePasswordUrl();
        }
        log.debug("Redirecting to url: {}", redirectUrl);
        response.sendRedirect(redirectUrl);
    }

    /**
     * What the user is told when the change did not go through.
     *
     * <p>Every failure used to arrive as "contact your administrator", which leaves the user with
     * nothing to act on and no way out: the password they were given has expired, this form is the
     * only way past it, and the form will not say what it wants. It is worse for the administrator
     * doing this on a first login, who is the administrator being referred to. The reasons a change
     * can fail are known and each already carries a message - the broken policy rules, or what the
     * authentication provider refused - so that message is what is shown.</p>
     *
     * <p>Anything else still falls back to the general message. An unexpected failure has no
     * message meant for a user, and what it does carry can describe the inside of the system.</p>
     */
    /**
     * @param encryptedParameter the field the page fills in
     * @param plainParameter the field it clears, read only when nothing encrypted arrived
     * @return the password, in the clear
     * @throws AuthenticationException when something encrypted arrived and could not be read. It
     *         is not quietly treated as the password itself: what the user typed is not what that
     *         would authenticate with, and the attempt would count against the account.
     */
    private String decrypted(HttpServletRequest request, String encryptedParameter, String plainParameter)
            throws AuthenticationException {
        String encrypted = SsoService.getFormParameter(request, encryptedParameter);
        if (StringUtils.isEmpty(encrypted)) {
            return SsoService.getFormParameter(request, plainParameter);
        }
        try {
            return LoginEnvelopeCrypto.decrypt(encrypted);
        } catch (Exception ex) {
            log.error("Unable to decrypt '{}' of a password change request: {}", encryptedParameter, ex.getMessage());
            log.debug("Exception", ex);
            throw new AuthenticationException(
                    SsoConstants.APP_ERROR_UNABLE_TO_EXTRACT_CREDENTIALS,
                    ssoContext.getLocalizationUtils().localize(
                            SsoConstants.APP_ERROR_UNABLE_TO_EXTRACT_CREDENTIALS,
                            (Locale) request.getAttribute(SsoConstants.LOCALE)),
                    ex);
        }
    }

    private String reasonToShow(HttpServletRequest request, Exception failure) {
        Locale locale = (Locale) request.getAttribute(SsoConstants.LOCALE);
        if (failure instanceof AuthenticationException && StringUtils.isNotBlank(failure.getMessage())) {
            return failure.getMessage();
        }
        return ssoContext.getLocalizationUtils().localize(
                SsoConstants.APP_ERROR_CONTACT_ADMINISTRATOR, locale);
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

    /**
     * Reads what the form submitted, decrypting the passwords the page encrypted.
     *
     * <p>This form used to post all three passwords as plain fields while the login form standing
     * in front of it encrypted the one it carries. That is backwards: this request carries the
     * password in force and the password replacing it, together, so it is worth more to anyone
     * reading it than the login it follows.</p>
     *
     * <p>The plain fields are still read when no encrypted one arrived, which is how the login
     * servlet does it too. The page clears them before it submits, so what arrives is the
     * encrypted form.</p>
     */
    private Credentials getUserCredentials(HttpServletRequest request) throws AuthenticationException {
        try {
            String username = SsoService.getFormParameter(request, USERNAME);
            String credentials = decrypted(request, ENCRYPTED_CREDENTIALS, CREDENTIALS);
            String credentialsNew1 = decrypted(request, ENCRYPTED_CREDENTIALS_NEW1, CREDENTIALS_NEW1);
            String credentialsNew2 = decrypted(request, ENCRYPTED_CREDENTIALS_NEW2, CREDENTIALS_NEW2);
            String profile = SsoService.getFormParameter(request, PROFILE);
            return StringUtils.isNotEmpty(username) &&
                    StringUtils.isNotEmpty(credentials) &&
                    StringUtils.isNotEmpty(credentialsNew1) &&
                    StringUtils.isNotEmpty(credentialsNew2) &&
                    StringUtils.isNotEmpty(profile)
                            ? new Credentials(username, credentials, credentialsNew1, credentialsNew2, profile)
                            : null;
        } catch (AuthenticationException ex) {
            // already says what went wrong and in which field; wrapping it again would lose that
            throw ex;
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
