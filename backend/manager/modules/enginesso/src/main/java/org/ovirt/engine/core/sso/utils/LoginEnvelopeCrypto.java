package org.ovirt.engine.core.sso.utils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public final class LoginEnvelopeCrypto {

    private static final Pattern RSA_PUBLIC_KEY_PATTERN =
            Pattern.compile("\\\"rsaPublicKey\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"])*)\\\""); //$NON-NLS-1$
    private static final Path CONFIG_PATH =
            Path.of("/etc/ovirt-engine/encryptor/config.json"); //$NON-NLS-1$
    private static final Path PRIVATE_KEY_PATH =
            Path.of("/etc/ovirt-engine/encryptor/private_pkcs8.der"); //$NON-NLS-1$

    private LoginEnvelopeCrypto() {
    }

    public static String readRsaPublicKey() throws IOException {
        String content = Files.readString(getConfigPath(), StandardCharsets.UTF_8);
        Matcher matcher = RSA_PUBLIC_KEY_PATTERN.matcher(content);
        if (!matcher.find()) {
            return null;
        }
        return unescapeJsonString(matcher.group(1)).trim();
    }

    public static String readRsaPublicKeyPem() throws IOException {
        String configuredKey = readRsaPublicKey();
        return formatRsaPublicKeyPem(configuredKey);
    }

    static String formatRsaPublicKeyPem(String configuredKey) throws IOException {
        if (configuredKey == null || configuredKey.trim().isEmpty()) {
            return configuredKey;
        }

        String base64Key = configuredKey
                .replace("-----BEGIN PUBLIC KEY-----", "") //$NON-NLS-1$ //$NON-NLS-2$
                .replace("-----END PUBLIC KEY-----", "") //$NON-NLS-1$ //$NON-NLS-2$
                .replaceAll("\\s", ""); //$NON-NLS-1$ //$NON-NLS-2$
        try {
            byte[] encodedKey = Base64.getDecoder().decode(base64Key);
            PublicKey publicKey = KeyFactory.getInstance("RSA") //$NON-NLS-1$
                    .generatePublic(new X509EncodedKeySpec(encodedKey));
            String pemBody = Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(publicKey.getEncoded());
            return "-----BEGIN PUBLIC KEY-----\n" + pemBody + "\n-----END PUBLIC KEY-----"; //$NON-NLS-1$ //$NON-NLS-2$
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IOException("rsaPublicKey is not a valid RSA X.509 public key", e); //$NON-NLS-1$
        }
    }

    public static String decrypt(String encryptedText) throws GeneralSecurityException, IOException {
        if (encryptedText == null || encryptedText.trim().isEmpty()) {
            return encryptedText;
        }
        return decrypt(encryptedText, readPrivateKey());
    }

    /**
     * Decrypts a REST API username while accepting the conventional plaintext
     * {@code @profile} suffix appended to its encrypted username component.
     */
    public static String decryptUsername(String encryptedUsername) throws GeneralSecurityException, IOException {
        if (encryptedUsername == null || encryptedUsername.trim().isEmpty()) {
            return encryptedUsername;
        }
        return decryptUsername(encryptedUsername, readPrivateKey());
    }

    static String decryptUsername(String encryptedUsername, PrivateKey privateKey) throws GeneralSecurityException {
        int profileSeparator = encryptedUsername == null ? -1 : encryptedUsername.lastIndexOf('@');
        if (profileSeparator < 0) {
            return decrypt(encryptedUsername, privateKey);
        }

        return decrypt(encryptedUsername.substring(0, profileSeparator), privateKey)
                + encryptedUsername.substring(profileSeparator);
    }

    static String decrypt(String encryptedText, PrivateKey privateKey) throws GeneralSecurityException {
        if (encryptedText == null || encryptedText.trim().isEmpty()) {
            return encryptedText;
        }

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText.trim());
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"); //$NON-NLS-1$
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec(
                "SHA-256", //$NON-NLS-1$
                "MGF1", //$NON-NLS-1$
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameterSpec);
        return new String(cipher.doFinal(encryptedBytes), StandardCharsets.UTF_8);
    }

    private static PrivateKey readPrivateKey() throws IOException, GeneralSecurityException {
        byte[] keyBytes = Files.readAllBytes(getPrivateKeyPath());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec); //$NON-NLS-1$
    }

    private static Path getConfigPath() {
        return CONFIG_PATH;
    }

    private static Path getPrivateKeyPath() {
        return PRIVATE_KEY_PATH;
    }

    private static String unescapeJsonString(String value) {
        return value
                .replace("\\\\", "\\") //$NON-NLS-1$ //$NON-NLS-2$
                .replace("\\/", "/") //$NON-NLS-1$ //$NON-NLS-2$
                .replace("\\\"", "\"") //$NON-NLS-1$ //$NON-NLS-2$
                .replace("\\n", "\n") //$NON-NLS-1$ //$NON-NLS-2$
                .replace("\\r", "\r") //$NON-NLS-1$ //$NON-NLS-2$
                .replace("\\t", "\t"); //$NON-NLS-1$ //$NON-NLS-2$
    }
}
