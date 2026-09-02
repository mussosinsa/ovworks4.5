package org.ovirt.engine.core.sso.servlets;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.api.extensions.aaa.Authn;
import org.ovirt.engine.core.sso.api.AuthResult;
import org.ovirt.engine.core.sso.api.AuthenticationException;
import org.ovirt.engine.core.sso.api.Credentials;
import org.ovirt.engine.core.sso.api.NonInteractiveAuth;
import org.ovirt.engine.core.sso.api.OAuthException;
import org.ovirt.engine.core.sso.api.SsoConstants;
import org.ovirt.engine.core.sso.api.SsoContext;
import org.ovirt.engine.core.sso.api.SsoSession;
import org.ovirt.engine.core.sso.service.AuthenticationService;
import org.ovirt.engine.core.sso.service.ExternalOIDCService;
import org.ovirt.engine.core.sso.service.NegotiateAuthService;
import org.ovirt.engine.core.sso.service.PasswordPolicyService;
import org.ovirt.engine.core.sso.service.SsoService;
import org.ovirt.engine.core.sso.utils.LoginEnvelopeCrypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuthTokenServlet extends HttpServlet {
    private static final long serialVersionUID = 7168485079055058668L;
    static final String PASSWORD_CHANGE_GRANT_TYPE =
            "urn:ovirt:params:oauth:grant-type:password-change"; //$NON-NLS-1$
    private static Logger log = LoggerFactory.getLogger(OAuthTokenServlet.class);

    protected SsoContext ssoContext;

    @Override
    public void init(ServletConfig config) {
        ssoContext = SsoService.getSsoContext(config.getServletContext());
    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            log.debug("Entered OAuthTokenServlet Query String: {}, Parameters : {}",
                    maskPassword(request.getQueryString()),
                    SsoService.getRequestParameters(request));
            handleRequest(request, response);
        } catch (OAuthException ex) {
            SsoService.sendJsonDataWithMessage(request, response, ex);
        } catch (AuthenticationException ex) {
            if (SsoConstants.APP_ERROR_USER_PASSWORD_EXPIRED_CHANGE_URL_PROVIDED.equals(ex.getErrorCode())) {
                sendPasswordChangeRequired(response, ex);
            } else {
                SsoService.sendJsonDataWithMessage(request, response, SsoConstants.ERR_CODE_ACCESS_DENIED, ex);
            }
        } catch (Exception ex) {
            SsoService.sendJsonDataWithMessage(request, response, SsoConstants.ERR_CODE_SERVER_ERROR, ex);
        }

    }

    protected void handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String grantType = SsoService.getRequestParameter(request,
                SsoConstants.JSON_GRANT_TYPE,
                SsoConstants.JSON_GRANT_TYPE);
        String scope = SsoService.getScopeRequestParameter(request, "");

        switch (grantType) {
        case "authorization_code":
            issueTokenForAuthCode(request, response, scope);
            break;
        case "password":
            if (SsoService.getSsoContext(request).getSsoLocalConfig().getBoolean("ENGINE_SSO_ENABLE_EXTERNAL_SSO")) {
                ExternalOIDCService.issueTokenUsingExternalOIDC(ssoContext, request, response);
            } else {
                handlePasswordGrantType(request, response, scope);
            }
            break;
        case PASSWORD_CHANGE_GRANT_TYPE:
            changePasswordAndIssueToken(request, response, scope);
            break;
        case "urn:ovirt:params:oauth:grant-type:http":
            if (SsoService.getSsoContext(request).getSsoLocalConfig().getBoolean("ENGINE_SSO_ENABLE_EXTERNAL_SSO")) {
                ExternalOIDCService.issueTokenUsingExternalOIDC(ssoContext, request, response);
            } else {
                issueTokenUsingHttpHeaders(request, response);
            }
            break;
        default:
            throw new OAuthException(SsoConstants.ERR_CODE_UNSUPPORTED_GRANT_TYPE,
                    SsoConstants.ERR_CODE_UNSUPPORTED_GRANT_TYPE_MSG);
        }
    }

    private void sendPasswordChangeRequired(HttpServletResponse response, AuthenticationException exception)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        SsoService.sendJsonData(response, buildPasswordChangeRequiredResponse(exception));
    }

    static Map<String, Object> buildPasswordChangeRequiredResponse(AuthenticationException exception) {
        Map<String, Object> error = new HashMap<>();
        error.put(SsoConstants.ERROR, "password_change_required"); //$NON-NLS-1$
        error.put(SsoConstants.ERROR_DESCRIPTION, exception.getMessage());
        error.put("password_change_grant_type", PASSWORD_CHANGE_GRANT_TYPE); //$NON-NLS-1$
        return error;
    }

    protected void changePasswordAndIssueToken(
            HttpServletRequest request,
            HttpServletResponse response,
            String scope) throws Exception {
        String encryptedUsername = SsoService.getRequestParameter(request, "encrypted_username"); //$NON-NLS-1$
        String encryptedCurrentPassword =
                SsoService.getRequestParameter(request, "encrypted_current_password"); //$NON-NLS-1$
        String encryptedNewPassword =
                SsoService.getRequestParameter(request, "encrypted_new_password"); //$NON-NLS-1$

        Credentials credentials = buildPasswordChangeCredentials(
                encryptedUsername,
                encryptedCurrentPassword,
                encryptedNewPassword,
                ssoContext,
                LoginEnvelopeCrypto::decryptUsername,
                LoginEnvelopeCrypto::decrypt);
        if (!SsoService.areCredentialsValid(request, credentials)) {
            throw new AuthenticationException(
                    SsoConstants.APP_ERROR_AUTHENTICATION_FAILED,
                    ssoContext.getLocalizationUtils().localize(
                            SsoConstants.APP_ERROR_AUTHENTICATION_FAILED,
                            (Locale) request.getAttribute(SsoConstants.LOCALE)));
        }

        List<String> policyViolations = PasswordPolicyService.validate(ssoContext, credentials);
        if (!policyViolations.isEmpty()) {
            throw new AuthenticationException(
                    SsoConstants.APP_ERROR_PASSWORD_POLICY_VIOLATION,
                    String.join(" ", policyViolations));
        }

        AuthenticationService.changePassword(ssoContext, request, credentials);
        PasswordPolicyService.recordPasswordHistory(ssoContext, credentials);
        try {
            SsoService.notifyClientOfPasswordChangeEvent(
                    ssoContext,
                    ssoContext.getSsoLocalConfig().getProperty("ENGINE_SSO_CLIENT_ID"), //$NON-NLS-1$
                    credentials.getUsernameWithProfile(),
                    true);
        } catch (Exception exception) {
            log.error("Unable to report password change event for user '{}'", //$NON-NLS-1$
                    credentials.getUsernameWithProfile(), exception);
        }

        credentials.setPassword(credentials.getNewCredentials());
        SsoSession ssoSession = handleIssueTokenForPasswd(request, scope, credentials);
        SsoService.sendJsonData(response, buildResponse(ssoSession));
    }

    static Credentials buildPasswordChangeCredentials(
            String encryptedUsername,
            String encryptedCurrentPassword,
            String encryptedNewPassword,
            SsoContext ssoContext,
            CredentialDecryptor usernameDecryptor,
            CredentialDecryptor passwordDecryptor) throws Exception {
        Credentials credentials = SsoService.translateUser(
                usernameDecryptor.decrypt(encryptedUsername),
                passwordDecryptor.decrypt(encryptedCurrentPassword),
                ssoContext);
        String newPassword = passwordDecryptor.decrypt(encryptedNewPassword);
        credentials.setCredentials(credentials.getPassword());
        credentials.setNewCredentials(newPassword);
        credentials.setConfirmedNewCredentials(newPassword);
        return credentials;
    }

    protected void validateClientAcceptHeader(SsoSession ssoSession, HttpServletRequest request) {
        SsoService.validateClientAcceptHeader(request);
    }

    protected void issueTokenForAuthCode(
            HttpServletRequest request,
            HttpServletResponse response,
            String scope) throws Exception {
        String[] clientIdAndSecret = SsoService.getClientIdClientSecret(request);
        SsoService.validateClientRequest(request,
                clientIdAndSecret[0],
                clientIdAndSecret[1],
                scope,
                null);
        SsoSession ssoSession = handleIssueTokenForAuthCode(request, clientIdAndSecret[0], scope);
        log.debug("Sending json response");
        SsoService.sendJsonData(response, buildResponse(ssoSession));
    }

    protected SsoSession handleIssueTokenForAuthCode(
            HttpServletRequest request,
            String clientId,
            String scope) {
        log.debug("Entered issueTokenForAuthCode");
        String authCode = SsoService.getRequestParameter(request,
                SsoConstants.HTTP_PARAM_AUTHORIZATION_CODE,
                SsoConstants.HTTP_PARAM_AUTHORIZATION_CODE);
        String accessToken = getTokenForAuthCode(authCode);
        SsoService.validateRequestScope(request, accessToken, scope);
        SsoSession ssoSession = SsoService.getSsoSession(request, clientId, accessToken, true);
        validateClientAcceptHeader(ssoSession, request);
        return ssoSession;
    }

    protected String getTokenForAuthCode(String authCode) {
        return ssoContext.getTokenForAuthCode(authCode);
    }

    private void handlePasswordGrantType(
            HttpServletRequest request,
            HttpServletResponse response,
            String scope) throws Exception {
        if (SsoService.scopeAsList(scope).contains("ovirt-ext=token:login-on-behalf")) {
            issueTokenForLoginOnBehalf(request, response, scope);
        } else {
            issueTokenForPasswd(request, response, scope);
        }
    }

    private void issueTokenForLoginOnBehalf(
            HttpServletRequest request,
            HttpServletResponse response,
            String scope) throws Exception {
        log.debug("Entered issueTokenForLoginOnBehalf");
        String[] clientIdAndSecret = SsoService.getClientIdClientSecret(request);
        String encryptedUsername = SsoService.getRequestParameter(request, "encrypted_username"); //$NON-NLS-1$
        if (StringUtils.isBlank(encryptedUsername)) {
            throw encryptedCredentialsRequired(request);
        }
        final String username;
        try {
            username = LoginEnvelopeCrypto.decryptUsername(encryptedUsername);
        } catch (Exception exception) {
            log.warn("Unable to decrypt REST API login-on-behalf username: {}",
                    exception.getClass().getSimpleName());
            log.debug("REST API login-on-behalf username decryption failure", exception);
            throw new AuthenticationException(
                    SsoConstants.APP_ERROR_AUTHENTICATION_FAILED,
                    ssoContext.getLocalizationUtils().localize(
                            SsoConstants.APP_ERROR_AUTHENTICATION_FAILED,
                            (Locale) request.getAttribute(SsoConstants.LOCALE)));
        }
        log.debug("Attempting to issueTokenForLoginOnBehalf for client: {}", clientIdAndSecret[0]);
        AuthenticationService.loginOnBehalf(ssoContext, request, username);
        String token = (String) request.getAttribute(SsoConstants.HTTP_REQ_ATTR_ACCESS_TOKEN);
        SsoService.validateRequestScope(request, token, scope);
        SsoSession ssoSession = SsoService.getSsoSession(request, token, true);
        if (ssoSession == null) {
            throw new OAuthException(SsoConstants.ERR_CODE_INVALID_GRANT,
                    ssoContext.getLocalizationUtils()
                            .localize(
                                    SsoConstants.APP_ERROR_AUTHORIZATION_GRANT_EXPIRED_FOR_USERNAME_PASSWORD,
                                    (Locale) request.getAttribute(SsoConstants.LOCALE)));
        }
        validateClientAcceptHeader(ssoSession, request);
        log.debug("Sending json response");
        SsoService.sendJsonData(response, buildResponse(ssoSession));
    }

    protected void issueTokenForPasswd(
            HttpServletRequest request,
            HttpServletResponse response,
            String scope) throws Exception {
        log.debug("Entered issueTokenForPasswd");
        Credentials credentials = null;
        try {
            credentials = getCredentials(request);
            SsoSession ssoSession = handleIssueTokenForPasswd(request, scope, credentials);
            log.debug("Sending json response");
            SsoService.sendJsonData(response, buildResponse(ssoSession));
        } catch (AuthenticationException ex) {
            if (SsoConstants.APP_ERROR_USER_PASSWORD_EXPIRED_CHANGE_URL_PROVIDED.equals(ex.getErrorCode())) {
                throw ex;
            }
            String profile = "N/A";
            if (credentials != null) {
                profile = credentials.getProfile() == null ? "N/A" : credentials.getProfile();
            }
            throw new AuthenticationException(
                    SsoConstants.APP_ERROR_CANNOT_AUTHENTICATE_USER_IN_DOMAIN,
                    String.format(
                            ssoContext.getLocalizationUtils().localize(
                                    SsoConstants.APP_ERROR_CANNOT_AUTHENTICATE_USER_IN_DOMAIN,
                                    (Locale) request.getAttribute(SsoConstants.LOCALE)),
                            credentials == null ? "N/A" : credentials.getUsername(),
                            profile,
                            ex.getMessage()));
        }
    }

    protected Credentials getCredentials(HttpServletRequest request) throws AuthenticationException {
        String encryptedUsername = SsoService.getRequestParameter(request, "encrypted_username"); //$NON-NLS-1$
        String encryptedPassword = SsoService.getRequestParameter(request, "encrypted_password"); //$NON-NLS-1$
        if (!hasEncryptedCredentials(encryptedUsername, encryptedPassword)) {
            throw encryptedCredentialsRequired(request);
        }
        try {
            return decryptCredentials(
                    encryptedUsername,
                    encryptedPassword,
                    ssoContext,
                    LoginEnvelopeCrypto::decryptUsername,
                    LoginEnvelopeCrypto::decrypt);
        } catch (Exception exception) {
            log.warn("Unable to decrypt REST API credentials: {}", exception.getClass().getSimpleName());
            log.debug("REST API credential decryption failure", exception);
            throw new AuthenticationException(
                    SsoConstants.APP_ERROR_AUTHENTICATION_FAILED,
                    ssoContext.getLocalizationUtils().localize(
                            SsoConstants.APP_ERROR_AUTHENTICATION_FAILED,
                            (Locale) request.getAttribute(SsoConstants.LOCALE)));
        }
    }

    static boolean hasEncryptedCredentials(String encryptedUsername, String encryptedPassword) {
        return StringUtils.isNotBlank(encryptedUsername) && StringUtils.isNotBlank(encryptedPassword);
    }

    private AuthenticationException encryptedCredentialsRequired(HttpServletRequest request) {
        String errorCode = SsoConstants.APP_ERROR_ENCRYPTED_CREDENTIALS_REQUIRED;
        return new AuthenticationException(
                errorCode,
                ssoContext.getLocalizationUtils().localize(
                        errorCode,
                        (Locale) request.getAttribute(SsoConstants.LOCALE)));
    }

    static Credentials decryptCredentials(
            String encryptedUsername,
            String encryptedPassword,
            SsoContext ssoContext,
            CredentialDecryptor usernameDecryptor,
            CredentialDecryptor passwordDecryptor) throws Exception {
        return SsoService.translateUser(
                usernameDecryptor.decrypt(encryptedUsername),
                passwordDecryptor.decrypt(encryptedPassword),
                ssoContext);
    }

    @FunctionalInterface
    interface CredentialDecryptor {
        String decrypt(String value) throws Exception;
    }

    protected SsoSession handleIssueTokenForPasswd(HttpServletRequest request,
            String scope,
            Credentials credentials) throws Exception {
        String token = null;
        if (credentials != null && SsoService.areCredentialsValid(request, credentials)) {
            AuthenticationService.handleCredentials(ssoContext, request, credentials, false);
            token = (String) request.getAttribute(SsoConstants.HTTP_REQ_ATTR_ACCESS_TOKEN);
        }
        log.debug("Attempting to issueTokenForPasswd");
        SsoSession ssoSession = SsoService.getSsoSessionFromRequest(request, token);
        if (ssoSession == null) {
            throw new OAuthException(SsoConstants.ERR_CODE_INVALID_GRANT,
                    ssoContext.getLocalizationUtils()
                            .localize(
                                    SsoConstants.APP_ERROR_AUTHORIZATION_GRANT_EXPIRED_FOR_USERNAME_PASSWORD,
                                    (Locale) request.getAttribute(SsoConstants.LOCALE)));
        }
        validateClientAcceptHeader(ssoSession, request);
        SsoService.validateRequestScope(request, token, scope);
        return ssoSession;
    }

    private void issueTokenUsingHttpHeaders(HttpServletRequest request, HttpServletResponse response) throws Exception {
        log.debug("Entered issueTokenUsingHttpHeaders");
        try {
            AuthResult authResult = null;
            for (NonInteractiveAuth auth : getAuthSeq()) {
                authResult = auth.doAuth(request, response);
                if (authResult.getStatus() == Authn.AuthResult.SUCCESS ||
                        authResult.getStatus() == Authn.AuthResult.NEGOTIATION_INCOMPLETE) {
                    break;
                }
            }
            if (authResult != null && authResult.getStatus() != Authn.AuthResult.SUCCESS) {
                log.debug("Authentication failed using http headers");
                List<String> schemes = (List<String>) request.getAttribute(NegotiateAuthService.REQUEST_SCHEMES_KEY);
                for (String scheme : new HashSet<>(schemes == null ? Collections.emptyList() : schemes)) {
                    response.setHeader("WWW-Authenticate", scheme);
                }
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            } else if (authResult != null && StringUtils.isNotEmpty(authResult.getToken())) {
                SsoSession ssoSession = SsoService.getSsoSessionFromRequest(request, authResult.getToken());
                if (ssoSession == null) {
                    throw new OAuthException(SsoConstants.ERR_CODE_INVALID_GRANT,
                            ssoContext.getLocalizationUtils()
                                    .localize(
                                            SsoConstants.APP_ERROR_AUTHORIZATION_GRANT_EXPIRED,
                                            (Locale) request.getAttribute(SsoConstants.LOCALE)));
                }
                validateClientAcceptHeader(ssoSession, request);
                log.debug("Sending json response");
                SsoService.sendJsonData(response, buildResponse(ssoSession));
            } else {
                throw new AuthenticationException(
                        SsoConstants.APP_ERROR_AUTHENTICATION_FAILED,
                        ssoContext.getLocalizationUtils().localize(
                                SsoConstants.APP_ERROR_AUTHENTICATION_FAILED,
                                (Locale) request.getAttribute(SsoConstants.LOCALE)));
            }
        } catch (Exception ex) {
            throw new AuthenticationException(
                    SsoConstants.APP_ERROR_AUTHENTICATION_FAILED,
                    String.format(
                            ssoContext.getLocalizationUtils().localize(
                                    SsoConstants.APP_ERROR_CANNOT_AUTHENTICATE_USER,
                                    (Locale) request.getAttribute(SsoConstants.LOCALE)),
                            ex.getMessage()));
        }
    }

    protected Map<String, Object> buildResponse(SsoSession ssoSession) {
        Map<String, Object> payload = new HashMap<>();
        payload.put(SsoConstants.JSON_ACCESS_TOKEN, ssoSession.getAccessToken());
        payload.put(SsoConstants.JSON_SCOPE, StringUtils.isEmpty(ssoSession.getScope()) ? "" : ssoSession.getScope());
        payload.put(SsoConstants.JSON_EXPIRES_IN, ssoSession.getValidTo().toString());
        payload.put(SsoConstants.JSON_TOKEN_TYPE, "bearer");
        return payload;
    }

    private List<NonInteractiveAuth> getAuthSeq() {
        String appAuthSeq = ssoContext.getSsoLocalConfig().getProperty("SSO_TOKEN_HTTP_LOGIN_SEQUENCE");
        List<NonInteractiveAuth> authSeqList = new ArrayList<>();
        if (StringUtils.isNotEmpty(appAuthSeq)) {
            for (char c : appAuthSeq.toCharArray()) {
                if (c == '~') {
                    continue;
                }
                try {
                    authSeqList.add(Enum.valueOf(NonInteractiveAuth.class, "" + c));
                } catch (IllegalArgumentException e) {
                    log.error("Unable to retrieve auth for value {}: {}", c, e.getMessage());
                    log.debug("Exception", e);
                }
            }
        }
        return authSeqList;
    }

    private String maskPassword(String queryString) {
        return StringUtils.isNotEmpty(queryString)
                ? queryString.replaceAll(
                        "(password|encrypted_password|encrypted_username|encrypted_current_password|" +
                                "encrypted_new_password)=[^&]+",
                        "$1=***")
                : queryString;
    }
}
