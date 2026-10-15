package org.ovirt.engine.core.uutils.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DekEnvelopeTest {

    private static final byte[] DEK = new byte[32];

    static {
        for (int i = 0; i < DEK.length; i++) {
            DEK[i] = (byte) i;
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    @AfterEach
    void forget() {
        System.clearProperty(DekEnvelope.DEK_PATH_PROPERTY);
        DekEnvelope.forget();
    }

    @Test
    void theDekIdIsTheOneTheEncryptorComputes() throws Exception {
        // hmac.new(bytes(range(32)), b"ovirt-engine dek id", hashlib.sha256).digest()[:8]
        assertEquals("78e44425a1c70b7e", hex(DekEnvelope.dekId(DEK)));
    }

    @Test
    void theEnvelopeIsTheEncryptorsOvenc002() throws Exception {
        byte[] plaintext = "ovworks00001".getBytes(StandardCharsets.UTF_8);
        byte[] envelope = DekEnvelope.encrypt(plaintext, DEK);
        // magic | version | DEK id | nonce, then ciphertext and the 16-byte tag
        assertArrayEquals("OVENC002".getBytes(StandardCharsets.US_ASCII), Arrays.copyOf(envelope, 8));
        assertEquals(1, envelope[8]);
        assertArrayEquals(DekEnvelope.dekId(DEK), Arrays.copyOfRange(envelope, 9, 17));
        assertEquals(29 + plaintext.length + 16, envelope.length);
        // Opened as encryptor.decrypt_envelope opens it: AES-256-GCM, the header as associated data.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(DEK, "AES"),
                new GCMParameterSpec(128, Arrays.copyOfRange(envelope, 17, 29)));
        cipher.updateAAD(Arrays.copyOf(envelope, 29));
        assertArrayEquals(plaintext, cipher.doFinal(envelope, 29, envelope.length - 29));
    }

    @Test
    void whatIsSealedOpensAndEveryEnvelopeIsDifferent() throws Exception {
        byte[] plaintext = "ovworks00001".getBytes(StandardCharsets.UTF_8);
        byte[] first = DekEnvelope.encrypt(plaintext, DEK);
        byte[] second = DekEnvelope.encrypt(plaintext, DEK);
        assertFalse(Arrays.equals(first, second));
        assertArrayEquals(plaintext, DekEnvelope.decrypt(first, DEK));
    }

    @Test
    void aChangedEnvelopeOrAnotherDekDoesNotOpen() throws Exception {
        byte[] envelope = DekEnvelope.encrypt("ovworks00001".getBytes(StandardCharsets.UTF_8), DEK);
        byte[] changed = envelope.clone();
        changed[changed.length - 1] ^= 1;
        assertThrows(DekEnvelope.DekException.class, () -> DekEnvelope.decrypt(changed, DEK));
        byte[] other = new byte[32];
        assertThrows(DekEnvelope.DekException.class, () -> DekEnvelope.decrypt(envelope, other));
    }

    @Test
    void theRuntimeDekIsReadFromTheFileTheLauncherNames(@TempDir Path dir) throws Exception {
        assertFalse(DekEnvelope.isAvailable());
        Path file = dir.resolve("dek");
        Files.write(file, DEK);
        System.setProperty(DekEnvelope.DEK_PATH_PROPERTY, file.toString());
        assertTrue(DekEnvelope.isAvailable());
        assertEquals("ovworks00001", DekEnvelope.decryptFromBase64(DekEnvelope.encryptToBase64("ovworks00001")));
    }

    @Test
    void aRuntimeDekOfTheWrongLengthIsRefused(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("dek");
        Files.write(file, new byte[16]);
        assertThrows(DekEnvelope.DekException.class, () -> DekEnvelope.readDek(file.toString()));
        assertThrows(DekEnvelope.DekException.class, () -> DekEnvelope.readDek(null));
    }
}
