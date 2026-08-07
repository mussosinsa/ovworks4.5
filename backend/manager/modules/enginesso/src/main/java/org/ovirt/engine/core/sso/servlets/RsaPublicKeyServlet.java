package org.ovirt.engine.core.sso.servlets;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.sso.api.OAuthException;
import org.ovirt.engine.core.sso.service.SsoService;
import org.ovirt.engine.core.sso.utils.LoginEnvelopeCrypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Downloads the RSA public key used to encrypt login credentials.
 */
public class RsaPublicKeyServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Logger log = LoggerFactory.getLogger(RsaPublicKeyServlet.class);
    private static final String PUBLIC_KEY_FILE_NAME = "public_key.pem"; //$NON-NLS-1$

    private final ClientSerialValidator clientSerialValidator;
    private final PublicKeyReader publicKeyReader;

    public RsaPublicKeyServlet() {
        this(SsoService::validateClientSerial, LoginEnvelopeCrypto::readRsaPublicKeyPem);
    }

    RsaPublicKeyServlet(ClientSerialValidator clientSerialValidator, PublicKeyReader publicKeyReader) {
        this.clientSerialValidator = clientSerialValidator;
        this.publicKeyReader = publicKeyReader;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            clientSerialValidator.validate(request);
        } catch (OAuthException e) {
            log.warn("RSA public key download rejected: {}", e.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid client serial"); //$NON-NLS-1$
            return;
        }

        final String publicKey;
        try {
            publicKey = publicKeyReader.read();
        } catch (IOException e) {
            log.error("Failed to read the RSA public key", e);
            response.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Unable to read RSA public key"); //$NON-NLS-1$
            return;
        }

        if (StringUtils.isBlank(publicKey)) {
            log.error("rsaPublicKey is missing from the encryptor configuration");
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "RSA public key is not configured"); //$NON-NLS-1$
            return;
        }

        response.setCharacterEncoding("UTF-8"); //$NON-NLS-1$
        response.setContentType("application/x-pem-file"); //$NON-NLS-1$
        response.setHeader(
                "Content-Disposition", //$NON-NLS-1$
                "attachment; filename=\"" + PUBLIC_KEY_FILE_NAME + "\""); //$NON-NLS-1$ //$NON-NLS-2$
        response.setHeader("Cache-Control", "no-store"); //$NON-NLS-1$ //$NON-NLS-2$
        try (PrintWriter writer = response.getWriter()) {
            writer.print(publicKey.trim());
            writer.print('\n');
        }
    }

    @FunctionalInterface
    interface ClientSerialValidator {
        void validate(HttpServletRequest request);
    }

    @FunctionalInterface
    interface PublicKeyReader {
        String read() throws IOException;
    }
}
