package org.ovirt.engine.core.sso.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import org.junit.jupiter.api.Test;

public class LoginEnvelopeCryptoTest {

    @Test
    public void formatsPublicKeyAsCanonicalPem() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        String unwrappedKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        String pem = LoginEnvelopeCrypto.formatRsaPublicKeyPem(unwrappedKey);
        String[] lines = pem.split("\\n"); //$NON-NLS-1$

        assertEquals("-----BEGIN PUBLIC KEY-----", lines[0]); //$NON-NLS-1$
        assertEquals("-----END PUBLIC KEY-----", lines[lines.length - 1]); //$NON-NLS-1$
        for (int index = 1; index < lines.length - 2; index++) {
            assertEquals(64, lines[index].length());
        }
        assertTrue(lines[lines.length - 2].length() <= 64);
    }
}
