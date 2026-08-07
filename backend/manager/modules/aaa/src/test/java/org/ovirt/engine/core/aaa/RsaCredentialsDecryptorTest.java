package org.ovirt.engine.core.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.junit.jupiter.api.Test;

class RsaCredentialsDecryptorTest {

    @Test
    void decryptsOaepSha256EncryptedCredential() throws Exception {
        KeyPair keyPair = getKeyPair();

        assertEquals("admin", RsaCredentialsDecryptor.decrypt(
                encrypt("admin", keyPair), keyPair.getPrivate()));
    }

    @Test
    void decryptsUsernameAndPreservesPlaintextProfile() throws Exception {
        KeyPair keyPair = getKeyPair();

        assertEquals("admin@internal", RsaCredentialsDecryptor.decryptUsername(
                encrypt("admin", keyPair) + "@internal", keyPair.getPrivate()));
    }

    @Test
    void decryptsUsernameWithEncryptedProfile() throws Exception {
        KeyPair keyPair = getKeyPair();

        assertEquals("admin@internal", RsaCredentialsDecryptor.decryptUsername(
                encrypt("admin@internal", keyPair), keyPair.getPrivate()));
    }

    @Test
    void rejectsPkcs1EncryptedCredential() throws Exception {
        KeyPair keyPair = getKeyPair();

        assertThrows(GeneralSecurityException.class, () -> RsaCredentialsDecryptor.decrypt(
                encryptPkcs1("admin", keyPair), keyPair.getPrivate()));
    }

    private static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String encrypt(String value, KeyPair keyPair) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT));
        return Base64.getEncoder().encodeToString(cipher.doFinal(value.getBytes(StandardCharsets.UTF_8)));
    }

    private static String encryptPkcs1(String value, KeyPair keyPair) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        return Base64.getEncoder().encodeToString(cipher.doFinal(value.getBytes(StandardCharsets.UTF_8)));
    }
}
