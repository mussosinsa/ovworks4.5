package org.ovirt.engine.core.uutils.crypto;

import java.nio.charset.StandardCharsets;
import java.security.DrbgParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The random bytes every secret of the engine is made from.
 *
 * <p>A Hash_DRBG over SHA-256 at 256-bit security strength (NIST SP 800-90A, and the Hash_DRBG of the
 * Korean approved random bit generators), the JDK's own DRBG. {@code new SecureRandom()} on Linux is
 * NativePRNG, which hands out what the kernel's generator gives; the kernel is still where this one's
 * entropy comes from, at instantiation and at every reseed, which is the place the standard gives it.</p>
 *
 * <p>One instance, shared: the JDK's DRBG is thread safe, and a session token, a nonce and a salt are
 * all requests to the same generator. Its personalization string sets it apart from any other DRBG in
 * the same JVM.</p>
 *
 * <p>When the JDK cannot give a DRBG, or the one it gives fails the health check, the bytes come from
 * {@code new SecureRandom()} as they did before, and {@link #describe()} says so. Refusing to make a
 * session token would stop every login; reporting the generator in use leaves that judgment to the
 * security verification, which looks for the line this class logs.</p>
 */
public final class ApprovedRandom {

    public static final String MECHANISM = "Hash_DRBG"; //$NON-NLS-1$
    public static final String DIGEST = "SHA-256"; //$NON-NLS-1$
    public static final int STRENGTH = 256;

    /** What the security verification looks for in engine.log. */
    public static final String LOG_PREFIX = "Approved random generator: "; //$NON-NLS-1$

    static final byte[] PERSONALIZATION = "ovirt-engine csprng v1".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$

    private static final Logger log = LoggerFactory.getLogger(ApprovedRandom.class);

    private ApprovedRandom() {
    }

    /** The generator, created the first time it is asked for. */
    private static final class Holder {
        static final Generator INSTANCE = create(ApprovedRandom::newDrbg);
    }

    /** A generator, and whether it is the approved one. */
    static final class Generator {
        private final SecureRandom random;
        private final boolean approved;
        private final String description;

        Generator(SecureRandom random, boolean approved, String description) {
            this.random = random;
            this.approved = approved;
            this.description = description;
        }

        SecureRandom random() {
            return random;
        }

        boolean approved() {
            return approved;
        }

        String description() {
            return description;
        }
    }

    /** The shared generator. Use it where {@code new SecureRandom()} was used. */
    public static SecureRandom get() {
        return Holder.INSTANCE.random();
    }

    /** Fills the array with random bytes from the shared generator. */
    public static void nextBytes(byte[] bytes) {
        get().nextBytes(bytes);
    }

    /** {@code count} random bytes from the shared generator. */
    public static byte[] bytes(int count) {
        byte[] bytes = new byte[count];
        nextBytes(bytes);
        return bytes;
    }

    /** Whether the shared generator is the Hash_DRBG rather than the fallback. */
    public static boolean isApproved() {
        return Holder.INSTANCE.approved();
    }

    /** The shared generator, in words a log or an audit can record. */
    public static String describe() {
        return Holder.INSTANCE.description();
    }

    static SecureRandom newDrbg() throws NoSuchAlgorithmException {
        return SecureRandom.getInstance(
                "DRBG", //$NON-NLS-1$
                DrbgParameters.instantiation(STRENGTH, DrbgParameters.Capability.RESEED_ONLY, PERSONALIZATION));
    }

    /** What the mechanism needs to be called by the JDK for the generator to count as the approved one. */
    static boolean isApprovedMechanism(String jdkDescription) {
        return jdkDescription != null
                && (jdkDescription.startsWith(MECHANISM + "," + DIGEST + "," + STRENGTH + ",") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                        || jdkDescription.startsWith("HMAC_DRBG," + DIGEST + "," + STRENGTH + ",")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    }

    /**
     * Builds the generator, and falls back to the one the engine used before when it cannot.
     *
     * <p>The mechanism the JDK's DRBG runs is set by the {@code securerandom.drbg.config} security
     * property, Hash_DRBG over SHA-256 unless someone changed it. It is read back rather than assumed:
     * a DRBG configured as something else is still used, since it is still a DRBG, but is not reported
     * as the approved one.</p>
     */
    static Generator create(DrbgFactory factory) {
        SecureRandom drbg;
        try {
            drbg = factory.newDrbg();
            healthCheck(drbg::nextBytes);
        } catch (Exception e) {
            String reason = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            String description = "NativePRNG fallback: " + reason; //$NON-NLS-1$
            log.error("{}{}", LOG_PREFIX, description); //$NON-NLS-1$
            return new Generator(new SecureRandom(), false, description);
        }
        String jdk = drbg.toString();
        boolean approved = isApprovedMechanism(jdk);
        String description = jdk + " (JDK DRBG, seeded by " //$NON-NLS-1$
                + (approved ? "the operating system)" : "the operating system; not the configured mechanism)"); //$NON-NLS-1$ //$NON-NLS-2$
        if (approved) {
            log.info("{}{}", LOG_PREFIX, description); //$NON-NLS-1$
        } else {
            log.warn("{}{}", LOG_PREFIX, description); //$NON-NLS-1$
        }
        return new Generator(drbg, approved, description);
    }

    /**
     * The continuous test of SP 800-90B 4.4 in its simplest form.
     *
     * <p>Two consecutive blocks that are equal, or a block of zeros, means the generator is broken -
     * better to fall back and say so than to hand out tokens that are all alike.</p>
     */
    static void healthCheck(Consumer<byte[]> generator) {
        byte[] first = new byte[32];
        byte[] second = new byte[32];
        generator.accept(first);
        generator.accept(second);
        if (Arrays.equals(first, second) || Arrays.equals(first, new byte[32])) {
            throw new IllegalStateException("DRBG failed its health check"); //$NON-NLS-1$
        }
    }

    /** Where the DRBG comes from: the JDK in use, a stand-in in tests. */
    @FunctionalInterface
    interface DrbgFactory {
        SecureRandom newDrbg() throws Exception;
    }
}
