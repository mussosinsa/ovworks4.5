package org.ovirt.engine.core.sso.servlets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.ovirt.engine.core.sso.api.OAuthException;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class RsaPublicKeyServletTest {

    private static final String PUBLIC_KEY =
            "-----BEGIN PUBLIC KEY-----\nkey-data\n-----END PUBLIC KEY-----"; //$NON-NLS-1$

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private RsaPublicKeyServlet.ClientSerialValidator validator;

    @Mock
    private RsaPublicKeyServlet.PublicKeyReader publicKeyReader;

    private StringWriter responseBody;
    private RsaPublicKeyServlet servlet;

    @BeforeEach
    public void setUp() throws Exception {
        responseBody = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseBody));
        servlet = new RsaPublicKeyServlet(validator, publicKeyReader);
    }

    @Test
    public void downloadsPublicKeyAfterSerialValidation() throws Exception {
        when(publicKeyReader.read()).thenReturn(PUBLIC_KEY);

        servlet.doGet(request, response);

        verify(validator).validate(request);
        verify(response).setContentType("application/x-pem-file"); //$NON-NLS-1$
        verify(response).setHeader(
                "Content-Disposition", //$NON-NLS-1$
                "attachment; filename=\"public_key.pem\""); //$NON-NLS-1$
        verify(response).setHeader("Cache-Control", "no-store"); //$NON-NLS-1$ //$NON-NLS-2$
        assertEquals(PUBLIC_KEY + "\n", responseBody.toString()); //$NON-NLS-1$
    }

    @Test
    public void rejectsInvalidClientSerial() throws Exception {
        doThrow(new OAuthException("unauthorized_client", "Invalid client serial")) //$NON-NLS-1$ //$NON-NLS-2$
                .when(validator).validate(request);

        servlet.doGet(request, response);

        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid client serial"); //$NON-NLS-1$
    }

    @Test
    public void returnsNotFoundWhenPublicKeyIsMissing() throws Exception {
        when(publicKeyReader.read()).thenReturn(null);

        servlet.doGet(request, response);

        verify(response).sendError(HttpServletResponse.SC_NOT_FOUND, "RSA public key is not configured"); //$NON-NLS-1$
    }
}
