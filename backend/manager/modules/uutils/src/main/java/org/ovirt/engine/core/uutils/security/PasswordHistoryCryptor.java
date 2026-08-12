package org.ovirt.engine.core.uutils.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Locale;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * One way hashing of the passwords kept in the engine password history.
 *
 * <p>The history exists solely to answer "has this user used this password before", so the
 * values are salted and stretched exactly like a stored credential would be. The encoded
 * form carries the parameters, which keeps previously written entries verifiable after the
 * cost factor is raised.</p>
 *
 * <p>Encoded form: {@code algorithm$iterations$base64(salt)$base64(hash)}</p>
 */
public class PasswordHistoryCryptor {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 210000;
    private static final int SALT_LENGTH = 32;
    private static final int KEY_LENGTH = 256;
    private static final String SEPARATOR = "$";

    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHistoryCryptor() {
    }

    /**
     * @param password the password to remember, never null
     * @return the encoded hash to be persisted
     */
    public static String hash(String password) {
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        byte[] hash = derive(password, salt, ITERATIONS);
        return String.join(SEPARATOR,
                ALGORITHM,
                String.valueOf(ITERATIONS),
                Base64.getEncoder().encodeToString(salt),
                Base64.getEncoder().encodeToString(hash));
    }

    /**
     * @param password the candidate password
     * @param encoded a value previously produced by {@link #hash(String)}
     * @return true when the candidate produces the stored hash. A malformed or unreadable
     *         entry never matches, so a corrupted history can not silently accept a password
     */
    public static boolean matches(String password, String encoded) {
        if (password == null || encoded == null) {
            return false;
        }
        String[] parts = encoded.split("\\" + SEPARATOR);
        if (parts.length != 4) {
            return false;
        }
        try {
            if (!ALGORITHM.equals(parts[0])) {
                return false;
            }
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            return MessageDigest.isEqual(expected, derive(password, salt, iterations));
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private static byte[] derive(String password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, KEY_LENGTH);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new IllegalStateException("Unable to hash the password history entry", ex);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * @return the principal the history is keyed by. The authz name used by the engine and the
     *         authn profile name used by sso differ by the conventional {@code -authz} suffix,
     *         both are normalized to the same key so that a password set through the
     *         administrative reset is seen by the interactive password change and vice versa
     */
    public static String principalKey(String loginName, String realm) {
        String name = loginName == null ? "" : loginName.trim().toLowerCase(Locale.ROOT);
        String normalizedRealm = realm == null ? "" : realm.trim().toLowerCase(Locale.ROOT);
        if (normalizedRealm.endsWith("-authz")) {
            normalizedRealm = normalizedRealm.substring(0, normalizedRealm.length() - "-authz".length());
        }
        int separator = name.indexOf('@');
        if (separator > 0) {
            name = name.substring(0, separator);
        }
        return name + "@" + normalizedRealm;
    }
}
