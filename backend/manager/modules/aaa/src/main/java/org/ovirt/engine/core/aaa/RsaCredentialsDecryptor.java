package org.ovirt.engine.core.aaa;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Decrypts REST API Basic-auth credentials encrypted with the login RSA public key.
 *
 * <p>The client sends each credential field as standard Base64 of an RSA-OAEP SHA-256
 * ciphertext. The matching private key remains on the engine host.</p>
 */
final class RsaCredentialsDecryptor {

    private static final Path PRIVATE_KEY_PATH =
            Path.of("/etc/ovirt-engine/encryptor/private_pkcs8.der"); //$NON-NLS-1$
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"; //$NON-NLS-1$
    private static final OAEPParameterSpec OAEP_PARAMETERS = new OAEPParameterSpec(
            "SHA-256", //$NON-NLS-1$
            "MGF1", //$NON-NLS-1$
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT);

    private RsaCredentialsDecryptor() {
    }

    static String decrypt(String value) throws GeneralSecurityException, IOException {
        return decrypt(value, readPrivateKey());
    }

    /**
     * Decrypt the username portion while preserving an optional plaintext SSO profile suffix.
     */
    static String decryptUsername(String value) throws GeneralSecurityException, IOException {
        return decryptUsername(value, readPrivateKey());
    }

    static String decrypt(String value, PrivateKey privateKey) throws GeneralSecurityException {
        byte[] encryptedBytes = Base64.getDecoder().decode(value);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_PARAMETERS);
        return new String(cipher.doFinal(encryptedBytes), StandardCharsets.UTF_8);
    }

    static String decryptUsername(String value, PrivateKey privateKey) throws GeneralSecurityException {
        int profileSeparator = value.lastIndexOf('@');
        if (profileSeparator == -1) {
            return decrypt(value, privateKey);
        }

        return decrypt(value.substring(0, profileSeparator), privateKey)
                + value.substring(profileSeparator);
    }

    private static PrivateKey readPrivateKey() throws IOException, GeneralSecurityException {
        byte[] keyBytes = Files.readAllBytes(PRIVATE_KEY_PATH);
        return KeyFactory.getInstance("RSA") //$NON-NLS-1$
                .generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }
}
