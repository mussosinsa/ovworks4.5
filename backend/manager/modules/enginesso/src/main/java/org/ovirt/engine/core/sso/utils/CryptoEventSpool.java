package org.ovirt.engine.core.sso.utils;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Leaves a failed cryptographic operation where the engine can record it in the audit log.
 *
 * <p>The single sign-on service opens the credentials clients seal to the engine's public key. It
 * has no audit-log writer of its own - it is a separate deployment, with a JDBC connection and
 * nothing that knows how an audit record is composed - so a cryptographic operation that failed
 * here reached engine.log and stopped there. The event list, which is where an administrator
 * looks, said nothing about a host whose login key had gone missing, and nothing about a client
 * presenting sealed values this engine cannot open.</p>
 *
 * <p>So it is written to the same spool the configuration-file cryptography already uses, and
 * {@code CryptoEventAuditManager} records it from there. That spool exists because most of that
 * cryptography also happens where no engine can record it; using it again keeps one reader, one
 * vocabulary and one place where an event name is turned into an audit log type.</p>
 *
 * <p>Nothing written here may carry a secret, a key, a ciphertext or a path: the entry names the
 * operation and gives a reason from a closed vocabulary, and nothing else. The exception it was
 * derived from goes to engine.log, which is read by fewer people than the event list is.</p>
 *
 * <p>Nothing here ever raises. The caller is in the middle of failing a login, and a spool that
 * cannot be written must not replace the reason it was failing with a reason about the spool.</p>
 */
public final class CryptoEventSpool {

    private static final Logger log = LoggerFactory.getLogger(CryptoEventSpool.class);

    /** Where the tools leave them, see ovirt_engine.cryptoevents and CryptoEventAuditManager. */
    static final String DEFAULT_SPOOL_DIR = "/var/lib/ovirt-engine/security/crypto-events"; //$NON-NLS-1$

    /** Overrides the location, for a test that must not write to the engine's state directory. */
    static final String SPOOL_DIR_PROPERTY = "ovirt.engine.sso.cryptoEventSpoolDir"; //$NON-NLS-1$

    /** The audit log type the engine raises for what this records. */
    static final String LOGIN_CREDENTIAL_DECRYPTION_FAILED = "LOGIN_CREDENTIAL_DECRYPTION_FAILED"; //$NON-NLS-1$

    /** A credential - the password, or either half of a password change - could not be opened. */
    public static final String SOURCE_CREDENTIAL = "sso-credential"; //$NON-NLS-1$

    /** A username could not be opened. */
    public static final String SOURCE_USERNAME = "sso-username"; //$NON-NLS-1$

    /** The reasons this writes. All of them are in the vocabulary the engine accepts. */
    static final String REASON_PRIVATE_KEY_UNAVAILABLE = "PRIVATE_KEY_UNAVAILABLE"; //$NON-NLS-1$
    static final String REASON_CIPHERTEXT_INVALID = "CIPHERTEXT_INVALID"; //$NON-NLS-1$
    static final String REASON_ALGORITHM_UNAVAILABLE = "ALGORITHM_UNAVAILABLE"; //$NON-NLS-1$
    static final String REASON_UNKNOWN = "UNKNOWN"; //$NON-NLS-1$

    /**
     * How long one reason waits before it is spooled again.
     *
     * <p>Unlike everything else that writes to this spool, this operation is reachable by anyone
     * who can reach the login page: a client sending rubbish in a loop would otherwise put one
     * file in the spool per attempt and one row in the audit log per file, and bury the event
     * list in a thing it had already said. Held per reason rather than overall, so that a login
     * key that has gone missing is still reported while bad ciphertexts are arriving.</p>
     *
     * <p>Every occurrence is in engine.log either way; this only decides how often the event list
     * is told. A flood therefore reads there as a steady drip, which is the fact worth recording:
     * that it is still happening.</p>
     */
    static final long THROTTLE_SECONDS = 60;

    private static final Set<PosixFilePermission> DIRECTORY_MODE =
            PosixFilePermissions.fromString("rwx------"); //$NON-NLS-1$

    private static final Set<PosixFilePermission> FILE_MODE =
            PosixFilePermissions.fromString("rw-------"); //$NON-NLS-1$

    /** When each reason was last spooled, so that {@link #THROTTLE_SECONDS} can be applied. */
    private static final ConcurrentMap<String, Instant> LAST_SPOOLED = new ConcurrentHashMap<>();

    private CryptoEventSpool() {
    }

    /**
     * Records that a login-path cryptographic operation did not succeed.
     *
     * @param source {@link #SOURCE_CREDENTIAL} or {@link #SOURCE_USERNAME}
     * @param error what the operation threw; never written down, only classified
     */
    public static void recordLoginDecryptionFailure(String source, Throwable error) {
        String reason = reasonFor(error);
        // Logged whatever the throttle decides: this is the record of every occurrence, and the
        // one place the exception itself is allowed to appear.
        log.warn("로그인 자격증명 복호화 실패; source='{}'; reason='{}'; error='{}'", //$NON-NLS-1$
                source, reason, error == null ? "" : error.toString()); //$NON-NLS-1$
        if (!shouldSpool(reason, Instant.now())) {
            return;
        }
        write(source, reason);
    }

    /**
     * @return whether this reason is spooled now, remembering the answer when it is
     */
    static boolean shouldSpool(String reason, Instant now) {
        Instant previous = LAST_SPOOLED.get(reason);
        if (previous != null && previous.plusSeconds(THROTTLE_SECONDS).isAfter(now)) {
            return false;
        }
        // Only the thread that wins the swap spools; the others are inside the window by the
        // time they get here, so a burst on many threads at once still leaves one entry.
        return previous == null
                ? LAST_SPOOLED.putIfAbsent(reason, now) == null
                : LAST_SPOOLED.replace(reason, previous, now);
    }

    /**
     * Classifies what went wrong, without keeping any of it.
     *
     * <p>By exception type rather than by message: a message can name the key file, and several
     * of the provider's carry the length or the offset of what was being decrypted.</p>
     */
    static String reasonFor(Throwable error) {
        if (error instanceof IOException || error instanceof InvalidKeySpecException) {
            // Reading or parsing the private key. Nothing was decrypted, and nothing on this
            // host can be until the key is back.
            return REASON_PRIVATE_KEY_UNAVAILABLE;
        }
        if (error instanceof NoSuchAlgorithmException
                || error instanceof NoSuchPaddingException
                || error instanceof NoSuchProviderException) {
            return REASON_ALGORITHM_UNAVAILABLE;
        }
        if (error instanceof BadPaddingException
                || error instanceof IllegalBlockSizeException
                || error instanceof IllegalArgumentException) {
            // The value presented is not something this key opens: not valid base64, not the
            // right length, or not sealed to this engine at all.
            return REASON_CIPHERTEXT_INVALID;
        }
        return REASON_UNKNOWN;
    }

    private static void write(String source, String reason) {
        try {
            Path spool = spoolDirectory();
            createDirectory(spool);
            String id = UUID.randomUUID().toString();
            byte[] entry = new ObjectMapper().writeValueAsBytes(Map.of(
                    "version", 1, //$NON-NLS-1$
                    "id", id, //$NON-NLS-1$
                    "timestamp", Instant.now().truncatedTo(ChronoUnit.SECONDS).toString(), //$NON-NLS-1$
                    "event", LOGIN_CREDENTIAL_DECRYPTION_FAILED, //$NON-NLS-1$
                    "source", source, //$NON-NLS-1$
                    "reason", reason)); //$NON-NLS-1$
            writeAtomically(spool, id, entry);
        } catch (Exception e) {
            // Said at debug and not above it: the failure this was recording has already been
            // logged at warn, and a spool that cannot be written must not look like the fault.
            log.debug("Unable to spool the login cryptography event", e); //$NON-NLS-1$
        }
    }

    /**
     * Writes the entry under a name nothing else will take, and only once it is whole.
     *
     * <p>The engine reads this directory while this is writing to it, so a half-written file must
     * never be one it can see. Built under a dotted name - which the engine skips for exactly
     * this reason - and renamed, which is atomic.</p>
     */
    private static void writeAtomically(Path spool, String id, byte[] entry) throws IOException {
        Path temporary = spool.resolve(".tmp-" + id); //$NON-NLS-1$
        try {
            Files.write(temporary, entry);
            trySetPermissions(temporary, FILE_MODE);
            Files.move(temporary, spool.resolve(id + ".json"), //$NON-NLS-1$
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException | RuntimeException e) {
            deleteQuietly(temporary);
            throw e;
        }
    }

    private static void createDirectory(Path spool) throws IOException {
        try {
            Files.createDirectory(spool, PosixFilePermissions.asFileAttribute(DIRECTORY_MODE));
        } catch (FileAlreadyExistsException e) {
            // Whoever made it first decides its permissions; engine-setup's tools make it too.
            return;
        } catch (IOException e) {
            if (!Files.isDirectory(spool)) {
                throw e;
            }
        }
    }

    private static void trySetPermissions(Path path, Set<PosixFilePermission> mode) {
        try {
            Files.setPosixFilePermissions(path, mode);
        } catch (IOException | RuntimeException e) {
            // A filesystem without POSIX permissions is not one the engine runs on, and the
            // entry carries no secret in any case.
            log.debug("Unable to set the permissions of {}", path, e); //$NON-NLS-1$
        }
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException | RuntimeException e) {
            log.debug("Unable to remove the partly written {}", path, e); //$NON-NLS-1$
        }
    }

    static Path spoolDirectory() {
        return Paths.get(System.getProperty(SPOOL_DIR_PROPERTY, DEFAULT_SPOOL_DIR));
    }

    /** Forgets what has been spooled, so that a test can drive the throttle from a known state. */
    static void reset() {
        LAST_SPOOLED.clear();
    }
}
