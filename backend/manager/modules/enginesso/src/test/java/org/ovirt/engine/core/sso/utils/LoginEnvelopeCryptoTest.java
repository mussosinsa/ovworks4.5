package org.ovirt.engine.core.sso.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

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

    @Test
    public void decryptsOaepSha256Ciphertext() throws Exception {
        KeyPair keyPair = generateKeyPair();

        assertEquals("user@internal", LoginEnvelopeCrypto.decrypt(
                encrypt("user@internal", keyPair), keyPair.getPrivate()));
    }

    @Test
    public void decryptsUsernameAndPreservesPlaintextProfileSuffix() throws Exception {
        KeyPair keyPair = generateKeyPair();

        assertEquals("user@internal", LoginEnvelopeCrypto.decryptUsername(
                encrypt("user", keyPair) + "@internal", keyPair.getPrivate()));
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String encrypt(String value, KeyPair keyPair) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"); //$NON-NLS-1$
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), new OAEPParameterSpec(
                "SHA-256", //$NON-NLS-1$
                "MGF1", //$NON-NLS-1$
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT));
        return Base64.getEncoder().encodeToString(cipher.doFinal(value.getBytes(StandardCharsets.UTF_8)));
    }
}
