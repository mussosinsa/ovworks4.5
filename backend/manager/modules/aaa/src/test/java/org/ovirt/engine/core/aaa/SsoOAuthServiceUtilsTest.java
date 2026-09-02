package org.ovirt.engine.core.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.message.BasicNameValuePair;
import org.junit.jupiter.api.Test;

class SsoOAuthServiceUtilsTest {

    @Test
    void forwardsEncryptedBasicCredentialsToSsoForDecryption() {
        HttpServletRequest request = basicRequest("encrypted-user", "encrypted-password");

        List<BasicNameValuePair> form =
                SsoOAuthServiceUtils.createEncryptedPasswordGrantForm(request, "ovirt-app-api");

        assertEquals("password", valueOf(form, "grant_type"));
        assertEquals("encrypted-user", valueOf(form, "encrypted_username"));
        assertEquals("encrypted-password", valueOf(form, "encrypted_password"));
        assertEquals("ovirt-app-api", valueOf(form, "scope"));
    }

    @Test
    void splitsBasicPayloadOnlyAtCredentialSeparator() {
        HttpServletRequest request = basicRequest("encrypted-user", "encrypted:password");

        List<BasicNameValuePair> form =
                SsoOAuthServiceUtils.createEncryptedPasswordGrantForm(request, "ovirt-app-api");

        assertEquals("encrypted-user", valueOf(form, "encrypted_username"));
        assertEquals("encrypted:password", valueOf(form, "encrypted_password"));
    }

    private static HttpServletRequest basicRequest(String username, String password) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        String payload = Base64.getEncoder().encodeToString(
                (username + ":" + password).getBytes(StandardCharsets.UTF_8));
        when(request.getHeader("Authorization")).thenReturn("Basic " + payload);
        return request;
    }

    private static String valueOf(List<BasicNameValuePair> form, String name) {
        return form.stream()
                .filter(parameter -> name.equals(parameter.getName()))
                .findFirst()
                .orElseThrow(AssertionError::new)
                .getValue();
    }
}
