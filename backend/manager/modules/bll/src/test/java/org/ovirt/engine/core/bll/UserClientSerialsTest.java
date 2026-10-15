package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck;

class UserClientSerialsTest {

    @Test
    void theDigestsAreReadFromTheUsersProperties() {
        String digest = ClientSerialCheck.digest("USER-0092");
        UserProfileProperty property = UserProfileProperty.builder()
                .withUserId(Guid.newGuid())
                .withName(UserClientSerials.PROPERTY)
                .withTypeJson()
                .withContent("\"" + digest + "\"") //$NON-NLS-1$ //$NON-NLS-2$
                .build();
        assertEquals(Set.of(digest), Set.copyOf(UserClientSerials.digests(List.of(property))));
    }

    @Test
    void theListIsWrittenWholeAndReadableByTheEngineAlone(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("client-serials");
        String first = ClientSerialCheck.digest("A");
        String second = ClientSerialCheck.digest("B");
        UserClientSerials.writeRegistry(file, List.of(second, first));
        UserClientSerials.writeRegistry(file, List.of(first));
        assertEquals(List.of(first), Files.readAllLines(file));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
        // Nothing is left behind beside it.
        try (var entries = Files.list(dir)) {
            assertEquals(1, entries.count());
        }
    }
}
