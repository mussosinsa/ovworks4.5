package org.ovirt.engine.core.sso.servlets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.sso.api.Credentials;
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
                value -> "encrypted-user".equals(value) ? "user@internal" : "secret");

        assertEquals("user", credentials.getUsername());
        assertEquals("internal", credentials.getProfile());
        assertEquals("secret", credentials.getPassword());
    }
}
