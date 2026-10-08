package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ovirt.engine.core.common.AuditLogType;

/**
 * The spool is a directory of files, not a call from inside the engine, and what it says ends
 * up in the audit log. So an entry is read as something to be checked rather than something to
 * be trusted, and an entry that does not check out is not recorded.
 */
class CryptoEventTest {

    @TempDir
    Path spool;

    private Optional<CryptoEvent> parse(String json) throws IOException {
        Path entry = Files.createTempFile(spool, "entry", ".json");
        Files.write(entry, json.getBytes(StandardCharsets.UTF_8));
        return CryptoEvent.parse(entry);
    }

    @Test
    void readsWhatTheToolsWrite() throws IOException {
        CryptoEvent event = parse("{\"version\":1,\"id\":\"abc\",\"timestamp\":\"2026-09-18T00:17:04Z\","
                + "\"event\":\"CONFIG_FILE_DECRYPTION_FAILED\",\"source\":\"engine-start\","
                + "\"file\":\"10-setup-database.conf\",\"scheme\":\"OVENC001\","
                + "\"reason\":\"AUTHENTICATION_FAILED\"}").orElseThrow();

        assertEquals(AuditLogType.CONFIG_FILE_DECRYPTION_FAILED, event.getAuditLogType());
        assertEquals("abc", event.getId());
        assertEquals("Configuration file 10-setup-database.conf could not be decrypted at 09:17 "
                + "(engine-start, OVENC001); reason: AUTHENTICATION_FAILED",
                event.describe(" at 09:17"));
    }

    @Test
    void doesNotLetAnEntryNameAFileOutsideItsOwnName() throws IOException {
        // The name goes into a message an administrator reads as the file that failed.
        assertEquals(Optional.empty(), parse("{\"version\":1,\"id\":\"a\","
                + "\"event\":\"CONFIG_FILE_DECRYPTION_FAILED\",\"source\":\"engine-start\","
                + "\"file\":\"../../etc/shadow\"}"));
        assertEquals(Optional.empty(), parse("{\"version\":1,\"id\":\"a\","
                + "\"event\":\"CONFIG_FILE_DECRYPTION_FAILED\",\"source\":\"engine-start\","
                + "\"file\":\"/etc/ovirt-engine/encryptor/passphrase\"}"));
    }

    @Test
    void doesNotRecordAReasonNobodyWrote() throws IOException {
        // The vocabulary is closed on both sides. Free text here is text of unknown origin
        // being printed into the audit log.
        assertEquals(Optional.empty(), parse("{\"version\":1,\"id\":\"a\","
                + "\"event\":\"CONFIG_FILE_DECRYPTION_FAILED\",\"source\":\"engine-start\","
                + "\"file\":\"f.conf\",\"reason\":\"vault token is hunter2\"}"));
    }

    @Test
    void doesNotRecordAnEventTypeItDoesNotKnow() throws IOException {
        // getAuditLogType() resolves the name; an unchecked one would be an exception in the
        // pass that is meant to be draining the spool.
        assertEquals(Optional.empty(), parse("{\"version\":1,\"id\":\"a\","
                + "\"event\":\"USER_ACCOUNT_LOCKED_BY_LOGIN_FAILURES\",\"source\":\"engine-start\","
                + "\"file\":\"f.conf\"}"));
        assertEquals(Optional.empty(), parse("{\"version\":1,\"id\":\"a\",\"event\":\"\","
                + "\"source\":\"engine-start\",\"file\":\"f.conf\"}"));
    }

    @Test
    void doesNotGuessAtAVersionItWasNotWrittenFor() throws IOException {
        assertEquals(Optional.empty(), parse("{\"version\":2,\"id\":\"a\","
                + "\"event\":\"CRYPTO_KEY_CREATED\",\"source\":\"engine-setup\"}"));
    }

    @Test
    void doesNotRecordAFileEventThatDoesNotSayWhichFile() throws IOException {
        assertEquals(Optional.empty(), parse("{\"version\":1,\"id\":\"a\","
                + "\"event\":\"CONFIG_FILE_DECRYPTION_FAILED\",\"source\":\"engine-start\"}"));
    }

    @Test
    void readsAKeyEventThatNamesNoFileBecauseItHasNone() throws IOException {
        CryptoEvent event = parse("{\"version\":1,\"id\":\"a\",\"event\":\"CRYPTO_KEY_CREATED\","
                + "\"source\":\"vault-passphrase\"}").orElseThrow();

        assertEquals(AuditLogType.CRYPTO_KEY_CREATED, event.getAuditLogType());
        assertTrue(event.describe("").contains("vault-passphrase"), event.describe(""));
    }

    @Test
    void namesTheFileAKeyWasCreatedForAndARejectedPassphrase() throws IOException {
        CryptoEvent created = parse("{\"version\":1,\"id\":\"a\",\"event\":\"CRYPTO_KEY_CREATED\","
                + "\"source\":\"encrypt-conf-files\",\"file\":\"10-setup-database.conf\","
                + "\"scheme\":\"OVENC001\"}").orElseThrow();
        assertEquals("KEK (key encryption key) was created for configuration file 10-setup-database.conf"
                + " (encrypt-conf-files, OVENC001)", created.describe(""));

        CryptoEvent rejected = parse("{\"version\":1,\"id\":\"b\","
                + "\"event\":\"CRYPTO_KEY_CREATION_FAILED\",\"source\":\"engine-setup\","
                + "\"reason\":\"PASSPHRASE_REJECTED\"}").orElseThrow();
        assertEquals("KEK (key encryption key) could not be created (engine-setup); reason: PASSPHRASE_REJECTED",
                rejected.describe(""));
    }

    @Test
    void namesTheKekAndTheDekInEveryKeyEvent() throws IOException {
        CryptoEvent kek = parse("{\"version\":1,\"id\":\"a\",\"event\":\"CRYPTO_KEY_CREATED\","
                + "\"source\":\"engine-setup\",\"scheme\":\"OVENC001\"}").orElseThrow();
        assertEquals("KEK (key encryption key) was created at T (engine-setup, OVENC001)", kek.describe(" at T"));

        CryptoEvent dek = parse("{\"version\":1,\"id\":\"b\",\"event\":\"CRYPTO_KEY_CREATED\","
                + "\"source\":\"encrypt-conf-files\",\"file\":\"dek.enc\",\"scheme\":\"OVDEK001\"}").orElseThrow();
        assertEquals("DEK (data encryption key) was created and stored wrapped by the KEK in dek.enc at T"
                + " (encrypt-conf-files, OVDEK001)", dek.describe(" at T"));

        CryptoEvent dekFailed = parse("{\"version\":1,\"id\":\"c\",\"event\":\"CRYPTO_KEY_CREATION_FAILED\","
                + "\"source\":\"kek-agent\",\"file\":\"dek.enc\",\"scheme\":\"OVDEK001\","
                + "\"reason\":\"RNG_UNAVAILABLE\"}").orElseThrow();
        assertEquals("DEK (data encryption key) could not be created (dek.enc) (kek-agent, OVDEK001);"
                + " reason: RNG_UNAVAILABLE", dekFailed.describe(""));

        CryptoEvent opened = parse("{\"version\":1,\"id\":\"d\",\"event\":\"DEK_DECRYPTION_COMPLETED\","
                + "\"source\":\"engine-start\",\"file\":\"dek.enc\",\"scheme\":\"OVDEK001\"}").orElseThrow();
        assertEquals(AuditLogType.DEK_DECRYPTION_COMPLETED, opened.getAuditLogType());
        assertEquals("DEK (data encryption key) was decrypted with the KEK (dek.enc) at T (engine-start, OVDEK001)",
                opened.describe(" at T"));

        CryptoEvent notOpened = parse("{\"version\":1,\"id\":\"e\",\"event\":\"DEK_DECRYPTION_FAILED\","
                + "\"source\":\"kek-agent\",\"file\":\"dek.enc\",\"scheme\":\"OVDEK001\","
                + "\"reason\":\"AUTHENTICATION_FAILED\"}").orElseThrow();
        assertEquals(AuditLogType.DEK_DECRYPTION_FAILED, notOpened.getAuditLogType());
        assertEquals("DEK (data encryption key) could not be decrypted with the KEK (dek.enc)"
                + " (kek-agent, OVDEK001); reason: AUTHENTICATION_FAILED", notOpened.describe(""));
    }

    @Test
    void anEngineStartWithoutTheKekInMemoryNamesTheKekAndTheDek() throws IOException {
        CryptoEvent dek = parse("{\"version\":1,\"id\":\"a\",\"event\":\"DEK_DECRYPTION_FAILED\","
                + "\"source\":\"engine-start\",\"file\":\"dek.enc\",\"scheme\":\"OVDEK001\","
                + "\"reason\":\"PASSPHRASE_UNAVAILABLE\"}").orElseThrow();
        assertEquals("DEK (data encryption key) could not be decrypted: the KEK (key encryption key) is not"
                + " available, its passphrase is not held in memory (dek.enc) at T (engine-start, OVDEK001);"
                + " reason: PASSPHRASE_UNAVAILABLE", dek.describe(" at T"));

        CryptoEvent file = parse("{\"version\":1,\"id\":\"b\",\"event\":\"CONFIG_FILE_DECRYPTION_FAILED\","
                + "\"source\":\"engine-start\",\"file\":\"10-setup-database.conf\",\"scheme\":\"OVENC002\","
                + "\"reason\":\"PASSPHRASE_UNAVAILABLE\"}").orElseThrow();
        assertEquals("Configuration file 10-setup-database.conf could not be decrypted at T (engine-start, OVENC002);"
                + " reason: PASSPHRASE_UNAVAILABLE (KEK not available)", file.describe(" at T"));

        CryptoEvent damaged = parse("{\"version\":1,\"id\":\"c\",\"event\":\"CONFIG_FILE_DECRYPTION_FAILED\","
                + "\"source\":\"engine-start\",\"file\":\"10-setup-database.conf\",\"scheme\":\"OVENC002\","
                + "\"reason\":\"FILE_DAMAGED\"}").orElseThrow();
        assertFalse(damaged.describe("").contains("KEK"), damaged.describe(""));
    }

    @Test
    void doesNotReadAFileTooBigToBeOneOfOurs() throws IOException {
        StringBuilder padding = new StringBuilder();
        while (padding.length() < CryptoEvent.MAX_SIZE) {
            padding.append('x');
        }

        assertEquals(Optional.empty(), parse("{\"version\":1,\"id\":\"a\","
                + "\"event\":\"CRYPTO_KEY_CREATED\",\"source\":\"engine-setup\",\"pad\":\""
                + padding + "\"}"));
    }

    @Test
    void doesNotFallOverOnSomethingThatIsNotAnEntryAtAll() throws IOException {
        assertEquals(Optional.empty(), parse("not json"));
        assertEquals(Optional.empty(), parse(""));
        assertEquals(Optional.empty(), parse("[]"));
    }
}
