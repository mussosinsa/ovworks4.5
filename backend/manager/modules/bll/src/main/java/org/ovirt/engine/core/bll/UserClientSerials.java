package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Collection;
import java.util.List;
import java.util.TreeSet;

import org.ovirt.engine.core.bll.aaa.CreateUserSessionCommand;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.utils.serialization.json.JsonObjectSerializer;
import org.ovirt.engine.core.uutils.crypto.DekEnvelope;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck;

/**
 * The users' terminal serials: kept per user encrypted under the DEK, in the profile property
 * {@value #PROPERTY}, and listed - still encrypted - for the checks made before a login in
 * {@link ClientSerialCheck#USER_SERIALS_FILE}.
 *
 * <p>A serial is never stored in the clear: each is an {@code OVENC002} envelope under the
 * installation's DEK ({@link DekEnvelope}), opened in memory to be compared with what a terminal
 * presents. Nor is it shown again once set.</p>
 */
public final class UserClientSerials {

    /** The per-user profile property that holds the user's terminal serial, sealed under the DEK. */
    public static final String PROPERTY = "CLIENT_SERIAL_ENC"; //$NON-NLS-1$

    /**
     * Where an earlier version kept a SHA-256 digest of the serial. A digest cannot be turned into
     * the serial, so it cannot be carried over: such a user is given its serial again, and setting
     * one removes this.
     */
    public static final String LEGACY_PROPERTY = "CLIENT_SERIAL_SHA256"; //$NON-NLS-1$

    private UserClientSerials() {
    }

    /** @return the envelope (base64) held in a stored property, or null */
    public static String envelopeFromContent(String content) {
        return CreateUserSessionCommand.dedicatedIpFromContent(content);
    }

    /** @return the serial held in a stored property, opened with the DEK */
    public static String serialFromContent(String content) throws DekEnvelope.DekException {
        String envelope = envelopeFromContent(content);
        if (envelope == null) {
            throw new DekEnvelope.DekException("No serial is stored"); //$NON-NLS-1$
        }
        return DekEnvelope.decryptFromBase64(envelope);
    }

    /** @return the property content a serial is stored as: its envelope, as a JSON string */
    public static String contentFor(String serial) throws DekEnvelope.DekException {
        return new JsonObjectSerializer().serializeUnformattedJson(DekEnvelope.encryptToBase64(serial));
    }

    /** @return the envelopes every user's serial is kept as */
    public static Collection<String> envelopes(List<UserProfileProperty> properties) {
        Collection<String> envelopes = new TreeSet<>();
        for (UserProfileProperty property : properties) {
            String envelope = envelopeFromContent(property.getContent());
            if (envelope != null) {
                envelopes.add(envelope);
            }
        }
        return envelopes;
    }

    /**
     * Whether another user than {@code userId} already has this serial: a serial names one user's
     * terminal. A stored serial that does not open cannot be compared and is not counted.
     */
    public static boolean isRegisteredToAnotherUser(List<UserProfileProperty> properties, Guid userId,
            String serial) {
        for (UserProfileProperty property : properties) {
            if (userId.equals(property.getUserId())) {
                continue;
            }
            try {
                if (serial.equals(serialFromContent(property.getContent()))) {
                    return true;
                }
            } catch (DekEnvelope.DekException e) {
                // Not comparable.
            }
        }
        return false;
    }

    /**
     * Writes the list the checks before a login read: replaced whole, so that a reader sees either
     * the old list or the new one, and readable by the engine's account alone.
     */
    public static synchronized void writeRegistry(Collection<String> envelopes) throws IOException {
        writeRegistry(Path.of(ClientSerialCheck.USER_SERIALS_FILE), envelopes);
    }

    static void writeRegistry(Path file, Collection<String> envelopes) throws IOException {
        Path temporary = Files.createTempFile(file.getParent(), ".client-serials", ".tmp"); //$NON-NLS-1$ //$NON-NLS-2$
        try {
            Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rw-------")); //$NON-NLS-1$
            StringBuilder content = new StringBuilder();
            for (String envelope : new TreeSet<>(envelopes)) {
                content.append(envelope).append('\n');
            }
            Files.writeString(temporary, content, StandardCharsets.US_ASCII);
            Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }
}
