package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import org.ovirt.engine.core.common.AuditLogType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * One thing the configuration-file cryptography did, as the tools left it behind.
 *
 * <p>The engine's database configuration is decrypted before the Java daemon exists, so the
 * result cannot be recorded when it happens. The tools write it to a spool and this reads it.
 * What is read is therefore a file on disk rather than a call from inside the engine, and it is
 * treated as such: every field is checked against what it is allowed to be, and an entry that
 * is not is set aside rather than recorded.</p>
 */
public final class CryptoEvent {

    private static final Logger log = LoggerFactory.getLogger(CryptoEvent.class);

    /** The only events an entry may name, each the audit log type it is recorded as. */
    private static final Set<String> EVENTS = Set.of(
            "CONFIG_FILE_DECRYPTION_COMPLETED", //$NON-NLS-1$
            "CONFIG_FILE_DECRYPTION_FAILED", //$NON-NLS-1$
            "CONFIG_FILE_ENCRYPTION_COMPLETED", //$NON-NLS-1$
            "CONFIG_FILE_ENCRYPTION_FAILED", //$NON-NLS-1$
            "CRYPTO_KEY_CREATED", //$NON-NLS-1$
            "CRYPTO_KEY_CREATION_FAILED"); //$NON-NLS-1$

    /**
     * The only reasons an entry may give.
     *
     * <p>A closed vocabulary rather than free text. The encryptor's own messages name
     * filesystem paths in several places, and a path says where the installation keeps its
     * keys; the audit log is read by more people than the engine log is.</p>
     */
    private static final Set<String> REASONS = Set.of(
            "UNKNOWN", //$NON-NLS-1$
            "AUTHENTICATION_FAILED", //$NON-NLS-1$
            "FILE_DAMAGED", //$NON-NLS-1$
            "VAULT_UNAVAILABLE", //$NON-NLS-1$
            "VAULT_RESPONSE_INVALID", //$NON-NLS-1$
            "PASSPHRASE_UNAVAILABLE", //$NON-NLS-1$
            "CONFIGURATION_INVALID", //$NON-NLS-1$
            "PATH_REJECTED", //$NON-NLS-1$
            "LEGACY_DENIED", //$NON-NLS-1$
            "ENCRYPTOR_MISSING"); //$NON-NLS-1$

    /** A basename and nothing else: no separator, no walking up, nothing exotic. */
    private static final Pattern FILE = Pattern.compile("[A-Za-z0-9._-]{1,255}");

    /** What ran it. Free of anything that could carry a value, for the same reason. */
    private static final Pattern SOURCE = Pattern.compile("[A-Za-z0-9._-]{1,64}");

    /** The envelope the file uses, as the encryptor spells its magic. */
    private static final Pattern SCHEME = Pattern.compile("OV[A-Z]{3}[0-9]{3}");

    /** Bigger than any entry this writes; a larger file is not one of ours. */
    static final long MAX_SIZE = 4096;

    private final String id;
    private final String event;
    private final String source;
    private final String file;
    private final String scheme;
    private final String reason;
    private final Instant timestamp;

    private CryptoEvent(String id, String event, String source, String file, String scheme,
            String reason, Instant timestamp) {
        this.id = id;
        this.event = event;
        this.source = source;
        this.file = file;
        this.scheme = scheme;
        this.reason = reason;
        this.timestamp = timestamp;
    }

    /** Distinguishes one entry from another, so the same one is not recorded twice. */
    public String getId() {
        return id;
    }

    /** When it happened, or null when the entry did not say. */
    public Instant getTimestamp() {
        return timestamp;
    }

    /** The audit log type this is recorded as. */
    public AuditLogType getAuditLogType() {
        return AuditLogType.valueOf(event);
    }

    /** What goes in the event list. */
    public String describe(String when) {
        StringBuilder message = new StringBuilder(subject())
                .append(when == null ? "" : when) //$NON-NLS-1$
                .append(" ("); //$NON-NLS-1$
        message.append(source);
        if (scheme != null) {
            message.append(", ").append(scheme); //$NON-NLS-1$
        }
        message.append(')');
        if (reason != null) {
            message.append("; reason: ").append(reason); //$NON-NLS-1$
        }
        return message.toString();
    }

    private String subject() {
        switch (event) {
            case "CONFIG_FILE_DECRYPTION_COMPLETED": //$NON-NLS-1$
                return "Configuration file " + file + " was decrypted"; //$NON-NLS-1$ //$NON-NLS-2$
            case "CONFIG_FILE_DECRYPTION_FAILED": //$NON-NLS-1$
                return "Configuration file " + file + " could not be decrypted"; //$NON-NLS-1$ //$NON-NLS-2$
            case "CONFIG_FILE_ENCRYPTION_COMPLETED": //$NON-NLS-1$
                return "Configuration file " + file + " was encrypted"; //$NON-NLS-1$ //$NON-NLS-2$
            case "CONFIG_FILE_ENCRYPTION_FAILED": //$NON-NLS-1$
                return "Configuration file " + file + " could not be encrypted"; //$NON-NLS-1$ //$NON-NLS-2$
            case "CRYPTO_KEY_CREATED": //$NON-NLS-1$
                return "An encryption key was created"; //$NON-NLS-1$
            default:
                return "An encryption key could not be created"; //$NON-NLS-1$
        }
    }

    /**
     * Reads one entry.
     *
     * @return the entry, or empty when the file is not one this can trust - which is recorded
     *         by the caller rather than passed over, because an entry that cannot be read is an
     *         account of a cryptographic operation that nobody is going to see
     */
    public static Optional<CryptoEvent> parse(Path path) {
        try {
            if (Files.size(path) > MAX_SIZE) {
                return Optional.empty();
            }
            JsonNode root = new ObjectMapper().readTree(path.toFile());
            if (root.path("version").asInt() != 1) { //$NON-NLS-1$
                return Optional.empty();
            }
            String event = root.path("event").asText(""); //$NON-NLS-1$ //$NON-NLS-2$
            String source = root.path("source").asText(""); //$NON-NLS-1$ //$NON-NLS-2$
            String id = root.path("id").asText(""); //$NON-NLS-1$ //$NON-NLS-2$
            if (!EVENTS.contains(event) || !SOURCE.matcher(source).matches() || id.isEmpty()) {
                return Optional.empty();
            }
            String file = text(root, "file", FILE); //$NON-NLS-1$
            if (event.startsWith("CONFIG_FILE_") && file == null) { //$NON-NLS-1$
                // The event is about a file and does not say which.
                return Optional.empty();
            }
            String reason = text(root, "reason", null); //$NON-NLS-1$
            if (reason != null && !REASONS.contains(reason)) {
                return Optional.empty();
            }
            return Optional.of(new CryptoEvent(
                    id,
                    event,
                    source,
                    file,
                    text(root, "scheme", SCHEME), //$NON-NLS-1$
                    reason,
                    parseTimestamp(root.path("timestamp").asText(null)))); //$NON-NLS-1$
        } catch (IOException | RuntimeException e) {
            log.warn("Unable to read the cryptography event {}: {}", path, e.getMessage()); //$NON-NLS-1$
            return Optional.empty();
        }
    }

    private static String text(JsonNode root, String field, Pattern allowed) {
        String value = root.path(field).asText(null);
        if (value == null || value.isEmpty()) {
            return null;
        }
        return allowed == null || allowed.matcher(value).matches() ? value : null;
    }

    private static Instant parseTimestamp(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
