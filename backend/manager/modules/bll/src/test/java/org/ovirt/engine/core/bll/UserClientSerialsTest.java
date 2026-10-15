package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.uutils.crypto.DekEnvelope;

class UserClientSerialsTest {

    private static final Guid USER = new Guid("aaaaaaaa-0000-0000-0000-000000000001");
    private static final Guid OTHER_USER = new Guid("bbbbbbbb-0000-0000-0000-000000000002");

    @TempDir
    static Path runtime;

    @BeforeAll
    static void handTheDekToThisRun() throws IOException {
        Path dek = runtime.resolve("dek");
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (31 - i);
        }
        Files.write(dek, key);
        System.setProperty(DekEnvelope.DEK_PATH_PROPERTY, dek.toString());
    }

    @AfterAll
    static void clear() {
        System.clearProperty(DekEnvelope.DEK_PATH_PROPERTY);
    }

    private static UserProfileProperty stored(Guid userId, String serial) throws Exception {
        return UserProfileProperty.builder()
                .withUserId(userId)
                .withName(UserClientSerials.PROPERTY)
                .withTypeJson()
                .withContent(UserClientSerials.contentFor(serial))
                .build();
    }

    @Test
    void aSerialIsStoredEncryptedUnderTheDekAndOpensAgain() throws Exception {
        UserProfileProperty property = stored(USER, "ovworks00092");
        assertFalse(property.getContent().contains("ovworks00092"));
        assertTrue(UserClientSerials.envelopeFromContent(property.getContent()).startsWith("T1ZFTkMwMDI")); // "OVENC002"
        assertEquals("ovworks00092", UserClientSerials.serialFromContent(property.getContent()));
        // A fresh nonce every time: the same serial is never stored the same way twice.
        assertNotEquals(property.getContent(), stored(USER, "ovworks00092").getContent());
    }

    @Test
    void aSerialAnotherUserHasCannotBeRegisteredAgain() throws Exception {
        List<UserProfileProperty> properties = List.of(stored(USER, "ovworks00092"), stored(OTHER_USER, "ovworks00093"));
        assertTrue(UserClientSerials.isRegisteredToAnotherUser(properties, OTHER_USER, "ovworks00092"));
        // Its own serial again is no clash, nor is a serial nobody has.
        assertFalse(UserClientSerials.isRegisteredToAnotherUser(properties, USER, "ovworks00092"));
        assertFalse(UserClientSerials.isRegisteredToAnotherUser(properties, USER, "ovworks00094"));
    }

    @Test
    void theListIsWrittenWholeEncryptedAndReadableByTheEngineAlone() throws Exception {
        Path dir = Files.createDirectory(runtime.resolve("state"));
        Path file = dir.resolve("client-serials");
        List<String> envelopes = List.copyOf(UserClientSerials.envelopes(
                List.of(stored(USER, "ovworks00092"), stored(OTHER_USER, "ovworks00093"))));
        UserClientSerials.writeRegistry(file, envelopes);
        UserClientSerials.writeRegistry(file, envelopes.subList(0, 1));
        List<String> written = Files.readAllLines(file);
        assertEquals(envelopes.subList(0, 1), written);
        assertFalse(written.get(0).contains("ovworks"));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
        try (var entries = Files.list(dir)) {
            assertEquals(1, entries.count());
        }
    }
}
