package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.sso.api.ClientInfo;
import org.ovirt.engine.core.sso.api.SsoConstants;
import org.ovirt.engine.core.sso.api.SsoContext;
import org.ovirt.engine.core.sso.utils.SsoLocalConfig;
import org.ovirt.engine.core.uutils.crypto.EnvelopePBE;

/**
 * A login refused through the REST API is posted to the SSO by the engine, from the engine host:
 * the audit record has to name the client the engine was serving, and only the engine may say
 * who that was.
 */
class ClientAddressTest {

    private static final String ENGINE_CLIENT = "ovirt-engine-core";
    private static final String SECRET = "engine-secret";
    private static final String SERVER = "192.168.10.5";
    private static final String CLIENT = "10.20.30.40";

    private SsoContext context;
    private Map<String, Object> attributes;

    @BeforeEach
    void setUp() throws Exception {
        context = mock(SsoContext.class);
        SsoLocalConfig config = mock(SsoLocalConfig.class);
        when(config.getProperty("ENGINE_SSO_CLIENT_ID")).thenReturn(ENGINE_CLIENT);
        when(context.getSsoLocalConfig()).thenReturn(config);
        when(context.getClienInfo(ENGINE_CLIENT)).thenReturn(new ClientInfo()
                .withClientId(ENGINE_CLIENT)
                .withClientSecret(EnvelopePBE.encode("PBKDF2WithHmacSHA1", 256, 4000, null, SECRET)));
        attributes = new HashMap<>();
    }

    private HttpServletRequest request(String remote, String sourceAddr, String clientId, String secret) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        ServletContext servletContext = mock(ServletContext.class);
        when(servletContext.getAttribute(SsoConstants.OVIRT_SSO_CONTEXT)).thenReturn(context);
        when(request.getServletContext()).thenReturn(servletContext);
        when(request.getRemoteAddr()).thenReturn(remote);
        when(request.getParameter(SsoConstants.HTTP_PARAM_SOURCE_ADDR)).thenReturn(sourceAddr);
        if (clientId != null) {
            when(request.getHeader(SsoConstants.HEADER_AUTHORIZATION)).thenReturn("Basic " + Base64.getEncoder()
                    .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8)));
        }
        doAnswer(i -> attributes.put(i.getArgument(0), i.getArgument(1)))
                .when(request).setAttribute(anyString(), any());
        when(request.getAttribute(anyString())).thenAnswer(i -> attributes.get(i.getArgument(0)));
        return request;
    }

    @Test
    void theEnginePostingForARestClientNamesTheClient() {
        assertEquals(CLIENT, ClientAddress.of(request(SERVER, CLIENT, ENGINE_CLIENT, SECRET)));
    }

    @Test
    void nobodyElseCanNameAnAddress() {
        // A client calling the SSO itself, with the address of somebody else in the form.
        assertEquals(CLIENT, ClientAddress.of(request(CLIENT, "1.2.3.4", null, null)));
        assertEquals(CLIENT, ClientAddress.of(request(CLIENT, "1.2.3.4", ENGINE_CLIENT, "guessed")));
        assertEquals(CLIENT, ClientAddress.of(request(CLIENT, "1.2.3.4", "another-client", SECRET)));
    }

    @Test
    void anythingButAnAddressIsNotTaken() {
        assertEquals(SERVER, ClientAddress.of(request(SERVER, "10.0.0.1\nforged line", ENGINE_CLIENT, SECRET)));
        assertTrue(ClientAddress.isAddress("fe80::1%eth0"));
        assertFalse(ClientAddress.isAddress("<script>"));
        assertFalse(ClientAddress.isAddress(null));
    }

    @Test
    void aBrowserIsKnownByItsOwnConnection() {
        assertEquals(CLIENT, ClientAddress.ofBrowser(request(CLIENT, null, null, null), "1.2.3.4"));
        assertEquals("1.2.3.4", ClientAddress.ofBrowser(request(null, null, null, null), "1.2.3.4"));
    }
}
