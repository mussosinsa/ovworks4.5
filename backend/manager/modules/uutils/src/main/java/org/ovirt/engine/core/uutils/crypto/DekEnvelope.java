package org.ovirt.engine.core.uutils.crypto;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encryption under the installation's DEK, in the envelope the encryptor writes ({@code OVENC002},
 * encryptor.py {@code encrypt_envelope}/{@code decrypt_envelope}), so that either side opens what
 * the other sealed.
 *
 * <pre>
 * header  = "OVENC002" | version (1) | DEK id (8) | nonce (12)
 * DEK id  = HMAC-SHA256(DEK, "ovirt-engine dek id")[0..8)
 * body    = AES-256-GCM(DEK, nonce, plaintext, AAD = header)   - ciphertext followed by the 16-byte tag
 * </pre>
 *
 * <p>The DEK itself is kept only wrapped by the KEK. The engine's launcher unwraps it for one run
 * into a private runtime file (runtime_dek.py) named by {@value #DEK_PATH_PROPERTY}; it is read
 * from there once and held in memory, and the file is overwritten and removed when the engine
 * stops. Nonces come from the approved generator ({@link ApprovedRandom}).</p>
 */
public final class DekEnvelope {

    /** The system property the launcher names the runtime copy of the DEK with. */
    public static final String DEK_PATH_PROPERTY = "ovirt.engine.dek.path"; //$NON-NLS-1$

    static final byte[] MAGIC = "OVENC002".getBytes(StandardCharsets.US_ASCII); //$NON-NLS-1$
    static final byte VERSION = 1;
    static final int DEK_SIZE = 32;
    static final int DEK_ID_SIZE = 8;
    static final int NONCE_SIZE = 12;
    static final int TAG_BITS = 128;
    static final int HEADER_SIZE = MAGIC.length + 1 + DEK_ID_SIZE + NONCE_SIZE;
    private static final byte[] DEK_ID_LABEL = "ovirt-engine dek id".getBytes(StandardCharsets.US_ASCII); //$NON-NLS-1$

    private static volatile byte[] runtimeDek;

    private DekEnvelope() {
    }

    /** The DEK could not be had, or an envelope does not open with it. */
    public static class DekException extends Exception {
        private static final long serialVersionUID = 4127908641287367123L;

        public DekException(String message) {
            super(message);
        }

        public DekException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** @return whether the engine was handed a DEK for this run */
    public static boolean isAvailable() {
        try {
            runtimeDek();
            return true;
        } catch (DekException e) {
            return false;
        }
    }

    /** Seals text under the runtime DEK. @return the envelope, base64 */
    public static String encryptToBase64(String plaintext) throws DekException {
        return Base64.getEncoder().encodeToString(
                encrypt(plaintext.getBytes(StandardCharsets.UTF_8), runtimeDek()));
    }

    /** Opens what {@link #encryptToBase64} sealed. */
    public static String decryptFromBase64(String envelope) throws DekException {
        byte[] data;
        try {
            data = Base64.getDecoder().decode(envelope.trim());
        } catch (IllegalArgumentException e) {
            throw new DekException("The envelope is not base64", e); //$NON-NLS-1$
        }
        byte[] plaintext = decrypt(data, runtimeDek());
        try {
            return new String(plaintext, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    static byte[] runtimeDek() throws DekException {
        byte[] dek = runtimeDek;
        if (dek != null) {
            return dek;
        }
        synchronized (DekEnvelope.class) {
            if (runtimeDek == null) {
                runtimeDek = readDek(System.getProperty(DEK_PATH_PROPERTY));
            }
            return runtimeDek;
        }
    }

    static byte[] readDek(String path) throws DekException {
        if (path == null || path.isEmpty()) {
            throw new DekException("The engine was not handed a DEK for this run"); //$NON-NLS-1$
        }
        byte[] dek;
        try {
            dek = Files.readAllBytes(Path.of(path));
        } catch (IOException e) {
            throw new DekException("The runtime copy of the DEK cannot be read", e); //$NON-NLS-1$
        }
        if (dek.length != DEK_SIZE) {
            Arrays.fill(dek, (byte) 0);
            throw new DekException("The runtime copy of the DEK has an unexpected length"); //$NON-NLS-1$
        }
        return dek;
    }

    static byte[] dekId(byte[] dek) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256"); //$NON-NLS-1$
        mac.init(new SecretKeySpec(dek, "HmacSHA256")); //$NON-NLS-1$
        return Arrays.copyOf(mac.doFinal(DEK_ID_LABEL), DEK_ID_SIZE);
    }

    static byte[] encrypt(byte[] plaintext, byte[] dek) throws DekException {
        try {
            byte[] nonce = ApprovedRandom.bytes(NONCE_SIZE);
            byte[] header = ByteBuffer.allocate(HEADER_SIZE)
                    .put(MAGIC).put(VERSION).put(dekId(dek)).put(nonce).array();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); //$NON-NLS-1$
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(TAG_BITS, nonce)); //$NON-NLS-1$
            cipher.updateAAD(header);
            byte[] body = cipher.doFinal(plaintext);
            return ByteBuffer.allocate(header.length + body.length).put(header).put(body).array();
        } catch (GeneralSecurityException e) {
            throw new DekException("Encryption under the DEK failed", e); //$NON-NLS-1$
        }
    }

    static byte[] decrypt(byte[] data, byte[] dek) throws DekException {
        if (data.length < HEADER_SIZE + TAG_BITS / 8) {
            throw new DekException("The envelope is truncated"); //$NON-NLS-1$
        }
        byte[] header = Arrays.copyOf(data, HEADER_SIZE);
        if (!Arrays.equals(Arrays.copyOf(header, MAGIC.length), MAGIC)) {
            throw new DekException("The envelope magic header is missing"); //$NON-NLS-1$
        }
        if (header[MAGIC.length] != VERSION) {
            throw new DekException("Unsupported envelope version: " + header[MAGIC.length]); //$NON-NLS-1$
        }
        try {
            byte[] keyId = Arrays.copyOfRange(header, MAGIC.length + 1, MAGIC.length + 1 + DEK_ID_SIZE);
            if (!MessageDigest.isEqual(keyId, dekId(dek))) {
                throw new DekException("The envelope is sealed under another DEK"); //$NON-NLS-1$
            }
            byte[] nonce = Arrays.copyOfRange(header, HEADER_SIZE - NONCE_SIZE, HEADER_SIZE);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); //$NON-NLS-1$
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(TAG_BITS, nonce)); //$NON-NLS-1$
            cipher.updateAAD(header);
            return cipher.doFinal(data, HEADER_SIZE, data.length - HEADER_SIZE);
        } catch (GeneralSecurityException e) {
            throw new DekException("Authentication failed: the envelope is damaged or modified", e); //$NON-NLS-1$
        }
    }

    /** For tests: forget the DEK read for this run. */
    static void forget() {
        synchronized (DekEnvelope.class) {
            if (runtimeDek != null) {
                Arrays.fill(runtimeDek, (byte) 0);
            }
            runtimeDek = null;
        }
    }
}
