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
import org.ovirt.engine.core.uutils.security.ClientSerialCheck;

/**
 * The users' terminal serials: kept per user as the SHA-256 digest of the serial, in the profile
 * property {@value #PROPERTY}, and listed for the checks made before a login in
 * {@link ClientSerialCheck#USER_SERIALS_FILE}.
 *
 * <p>Only digests are kept anywhere. A serial is checked by digesting what the terminal presents,
 * so the serial itself is never stored and cannot be read back - not even by an administrator,
 * who sets a new one instead.</p>
 */
public final class UserClientSerials {

    /** The per-user profile property that holds the digest of the user's terminal serial. */
    public static final String PROPERTY = "CLIENT_SERIAL_SHA256"; //$NON-NLS-1$

    private UserClientSerials() {
    }

    /** @return the digest held in a stored property, or null */
    public static String digestFromContent(String content) {
        return CreateUserSessionCommand.dedicatedIpFromContent(content);
    }

    /** @return the digests every user's serial is kept as */
    public static Collection<String> digests(List<UserProfileProperty> properties) {
        Collection<String> digests = new TreeSet<>();
        for (UserProfileProperty property : properties) {
            String digest = digestFromContent(property.getContent());
            if (digest != null) {
                digests.add(digest);
            }
        }
        return digests;
    }

    /**
     * Writes the list the checks before a login read: replaced whole, so that a reader sees either
     * the old list or the new one, and readable by the engine's account alone.
     */
    public static synchronized void writeRegistry(Collection<String> digests) throws IOException {
        writeRegistry(Path.of(ClientSerialCheck.USER_SERIALS_FILE), digests);
    }

    static void writeRegistry(Path file, Collection<String> digests) throws IOException {
        Path temporary = Files.createTempFile(file.getParent(), ".client-serials", ".tmp"); //$NON-NLS-1$ //$NON-NLS-2$
        try {
            Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rw-------")); //$NON-NLS-1$
            StringBuilder content = new StringBuilder();
            for (String digest : new TreeSet<>(digests)) {
                content.append(digest).append('\n');
            }
            Files.writeString(temporary, content, StandardCharsets.US_ASCII);
            Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }
}
