package org.ovirt.engine.core.sso.servlets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.sso.api.AuthenticationException;
import org.ovirt.engine.core.sso.api.Credentials;
import org.ovirt.engine.core.sso.api.SsoConstants;
import org.ovirt.engine.core.sso.api.SsoContext;

class OAuthTokenServletTest {

    @Test
    void requiresBothEncryptedCredentialParameters() {
        assertTrue(OAuthTokenServlet.hasEncryptedCredentials("encrypted-user", "encrypted-password"));
        assertFalse(OAuthTokenServlet.hasEncryptedCredentials("encrypted-user", null));
        assertFalse(OAuthTokenServlet.hasEncryptedCredentials(null, "encrypted-password"));
    }

    @Test
    void decryptsEncryptedRestCredentialsBeforeAuthentication() throws Exception {
        SsoContext context = mock(SsoContext.class);
        when(context.getSsoProfiles()).thenReturn(Arrays.asList("internal"));

        Credentials credentials = OAuthTokenServlet.decryptCredentials(
                "encrypted-user",
                "encrypted-password",
                context,
                value -> "user@internal",
                value -> "secret");

        assertEquals("user", credentials.getUsername());
        assertEquals("internal", credentials.getProfile());
        assertEquals("secret", credentials.getPassword());
    }

    @Test
    void tellsRestClientHowToChangeAnExpiredPassword() {
        AuthenticationException exception = new AuthenticationException(
                SsoConstants.APP_ERROR_USER_PASSWORD_EXPIRED_CHANGE_URL_PROVIDED,
                "Password change required");

        Map<String, Object> response = OAuthTokenServlet.buildPasswordChangeRequiredResponse(exception);

        assertEquals("password_change_required", response.get(SsoConstants.ERROR));
        assertEquals("Password change required", response.get(SsoConstants.ERROR_DESCRIPTION));
        assertEquals(
                OAuthTokenServlet.PASSWORD_CHANGE_GRANT_TYPE,
                response.get("password_change_grant_type"));
    }

    @Test
    void decryptsCurrentAndNewCredentialsForPasswordChange() throws Exception {
        SsoContext context = mock(SsoContext.class);
        when(context.getSsoProfiles()).thenReturn(Arrays.asList("internal"));

        Credentials credentials = OAuthTokenServlet.buildPasswordChangeCredentials(
                "encrypted-user",
                "encrypted-current",
                "encrypted-new",
                context,
                value -> "user@internal",
                value -> "encrypted-current".equals(value) ? "Current1!" : "Replacement2!");

        assertEquals("user", credentials.getUsername());
        assertEquals("internal", credentials.getProfile());
        assertEquals("Current1!", credentials.getCredentials());
        assertEquals("Replacement2!", credentials.getNewCredentials());
        assertEquals("Replacement2!", credentials.getConfirmedNewCredentials());
    }
}
