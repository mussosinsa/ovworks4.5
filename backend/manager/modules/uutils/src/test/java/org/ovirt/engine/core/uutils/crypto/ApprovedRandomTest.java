package org.ovirt.engine.core.uutils.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

public class ApprovedRandomTest {

    @Test
    void theSharedGeneratorIsAHashDrbgOverSha256At256Bits() {
        assertTrue(ApprovedRandom.isApproved(), ApprovedRandom.describe());
        assertEquals("DRBG", ApprovedRandom.get().getAlgorithm());
        assertTrue(ApprovedRandom.get().toString().startsWith("Hash_DRBG,SHA-256,256,"),
                ApprovedRandom.get().toString());
        assertTrue(ApprovedRandom.describe().startsWith("Hash_DRBG,SHA-256,256,"), ApprovedRandom.describe());
    }

    @Test
    void itIsOneGeneratorAndItGivesDifferentBytesEachTime() {
        assertTrue(ApprovedRandom.get() == ApprovedRandom.get());
        byte[] first = ApprovedRandom.bytes(32);
        byte[] second = ApprovedRandom.bytes(32);
        assertEquals(32, first.length);
        assertFalse(Arrays.equals(first, second));
    }

    @Test
    void aJdkWithoutADrbgFallsBackToWhatTheEngineUsedBefore() {
        ApprovedRandom.Generator generator = ApprovedRandom.create(() -> {
            throw new NoSuchAlgorithmException("DRBG SecureRandom not available");
        });

        assertFalse(generator.approved());
        assertNotNull(generator.random());
        assertTrue(generator.description().startsWith("NativePRNG fallback: DRBG SecureRandom not available"),
                generator.description());
    }

    @Test
    void aGeneratorThatRepeatsItselfFailsTheHealthCheck() {
        SecureRandom stuck = new SecureRandom() {
            private static final long serialVersionUID = 1L;

            @Override
            public void nextBytes(byte[] bytes) {
                Arrays.fill(bytes, (byte) 7);
            }
        };

        assertThrows(IllegalStateException.class, () -> ApprovedRandom.healthCheck(stuck::nextBytes));
        assertFalse(ApprovedRandom.create(() -> stuck).approved());
    }

    @Test
    void onlyAHashOrHmacDrbgOverSha256At256BitsCountsAsApproved() {
        assertTrue(ApprovedRandom.isApprovedMechanism("Hash_DRBG,SHA-256,256,reseed_only"));
        assertTrue(ApprovedRandom.isApprovedMechanism("HMAC_DRBG,SHA-256,256,pr_and_reseed"));
        assertFalse(ApprovedRandom.isApprovedMechanism("CTR_DRBG,AES-256,256,reseed_only,use_df"));
        assertFalse(ApprovedRandom.isApprovedMechanism("Hash_DRBG,SHA-256,128,reseed_only"));
        assertFalse(ApprovedRandom.isApprovedMechanism("NativePRNG"));
        assertFalse(ApprovedRandom.isApprovedMechanism(null));
    }
}
