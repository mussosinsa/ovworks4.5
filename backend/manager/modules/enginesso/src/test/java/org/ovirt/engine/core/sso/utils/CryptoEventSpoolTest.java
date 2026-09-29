package org.ovirt.engine.core.sso.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class CryptoEventSpoolTest {

    @TempDir
    public Path spool;

    private String previousSpoolDir;

    @BeforeEach
    public void redirectTheSpool() {
        previousSpoolDir = System.getProperty(CryptoEventSpool.SPOOL_DIR_PROPERTY);
        System.setProperty(CryptoEventSpool.SPOOL_DIR_PROPERTY, spool.resolve("events").toString());
        CryptoEventSpool.reset();
    }

    @AfterEach
    public void restoreTheSpool() {
        if (previousSpoolDir == null) {
            System.clearProperty(CryptoEventSpool.SPOOL_DIR_PROPERTY);
        } else {
            System.setProperty(CryptoEventSpool.SPOOL_DIR_PROPERTY, previousSpoolDir);
        }
        CryptoEventSpool.reset();
    }

    @Test
    public void writesTheEventTheEngineRecordsAndNothingElse() throws Exception {
        CryptoEventSpool.recordLoginDecryptionFailure(
                CryptoEventSpool.SOURCE_CREDENTIAL, new BadPaddingException("block 17 of /etc/key"));

        JsonNode entry = onlyEntry();
        assertEquals(1, entry.path("version").asInt());
        assertEquals(CryptoEventSpool.LOGIN_CREDENTIAL_DECRYPTION_FAILED, entry.path("event").asText());
        assertEquals(CryptoEventSpool.SOURCE_CREDENTIAL, entry.path("source").asText());
        assertEquals(CryptoEventSpool.REASON_CIPHERTEXT_INVALID, entry.path("reason").asText());
        assertFalse(entry.path("id").asText().isEmpty());
        // A timestamp the engine's Instant.parse reads, and a second's resolution as the tools write.
        assertTrue(entry.path("timestamp").asText().endsWith("Z"));
        Instant.parse(entry.path("timestamp").asText());
        // Nothing the exception said may be in the entry: several provider messages name the key
        // file, and a path says where the installation keeps its keys.
        assertFalse(entry.toString().contains("/etc/key"));
        assertFalse(entry.toString().contains("block 17"));
    }

    @Test
    public void namesTheReasonByTypeSoAMissingKeyIsNotABadCiphertext() {
        assertEquals(CryptoEventSpool.REASON_PRIVATE_KEY_UNAVAILABLE,
                CryptoEventSpool.reasonFor(new IOException("no such file")));
        assertEquals(CryptoEventSpool.REASON_PRIVATE_KEY_UNAVAILABLE,
                CryptoEventSpool.reasonFor(new InvalidKeySpecException("not PKCS#8")));
        assertEquals(CryptoEventSpool.REASON_ALGORITHM_UNAVAILABLE,
                CryptoEventSpool.reasonFor(new NoSuchPaddingException("OAEP")));
        assertEquals(CryptoEventSpool.REASON_CIPHERTEXT_INVALID,
                CryptoEventSpool.reasonFor(new BadPaddingException("decryption error")));
        // Base64 that will not decode arrives as this, unchecked and undeclared.
        assertEquals(CryptoEventSpool.REASON_CIPHERTEXT_INVALID,
                CryptoEventSpool.reasonFor(new IllegalArgumentException("Illegal base64 character")));
        assertEquals(CryptoEventSpool.REASON_UNKNOWN,
                CryptoEventSpool.reasonFor(new IllegalStateException("something else")));
        assertEquals(CryptoEventSpool.REASON_UNKNOWN, CryptoEventSpool.reasonFor(null));
    }

    @Test
    public void spoolsOneEntryPerReasonPerWindowSoALoopCannotFillTheEventList() throws Exception {
        for (int attempt = 0; attempt < 50; attempt++) {
            CryptoEventSpool.recordLoginDecryptionFailure(
                    CryptoEventSpool.SOURCE_CREDENTIAL, new BadPaddingException("rubbish"));
        }

        assertEquals(1, entries().size());
    }

    @Test
    public void aMissingKeyIsStillReportedWhileBadCiphertextsAreArriving() throws Exception {
        CryptoEventSpool.recordLoginDecryptionFailure(
                CryptoEventSpool.SOURCE_CREDENTIAL, new BadPaddingException("rubbish"));
        CryptoEventSpool.recordLoginDecryptionFailure(
                CryptoEventSpool.SOURCE_CREDENTIAL, new IOException("key is gone"));

        List<String> reasons = entries().stream()
                .map(entry -> entry.path("reason").asText())
                .sorted()
                .collect(Collectors.toList());
        assertEquals(List.of(CryptoEventSpool.REASON_CIPHERTEXT_INVALID,
                CryptoEventSpool.REASON_PRIVATE_KEY_UNAVAILABLE), reasons);
    }

    @Test
    public void theWindowIsHeldPerReasonAndOpensAgainWhenItHasPassed() {
        Instant first = Instant.parse("2026-09-29T00:00:00Z");

        assertTrue(CryptoEventSpool.shouldSpool(CryptoEventSpool.REASON_CIPHERTEXT_INVALID, first));
        assertFalse(CryptoEventSpool.shouldSpool(CryptoEventSpool.REASON_CIPHERTEXT_INVALID,
                first.plusSeconds(CryptoEventSpool.THROTTLE_SECONDS - 1)));
        assertTrue(CryptoEventSpool.shouldSpool(CryptoEventSpool.REASON_CIPHERTEXT_INVALID,
                first.plusSeconds(CryptoEventSpool.THROTTLE_SECONDS)));
    }

    @Test
    public void leavesNothingHalfWrittenForTheEngineToRead() throws Exception {
        CryptoEventSpool.recordLoginDecryptionFailure(
                CryptoEventSpool.SOURCE_USERNAME, new IOException("key is gone"));

        // The engine reads *.json and skips dotted names, so a temporary file left behind would
        // not be recorded - but it would accumulate, one per failure, forever.
        try (Stream<Path> files = Files.list(CryptoEventSpool.spoolDirectory())) {
            List<String> names = files.map(path -> path.getFileName().toString())
                    .sorted()
                    .collect(Collectors.toList());
            assertEquals(1, names.size());
            assertTrue(names.get(0).endsWith(".json"), names.get(0));
            assertFalse(names.get(0).startsWith("."), names.get(0));
        }
    }

    @Test
    public void aSpoolItCannotWriteIsNotAFailureTheCallerHearsAbout() throws Exception {
        // A file where the directory should be: creating it fails, and so does everything after.
        Path blocked = spool.resolve("blocked");
        Files.writeString(blocked, "not a directory");
        System.setProperty(CryptoEventSpool.SPOOL_DIR_PROPERTY, blocked.toString());

        CryptoEventSpool.recordLoginDecryptionFailure(
                CryptoEventSpool.SOURCE_CREDENTIAL, new IOException("key is gone"));
    }

    private List<JsonNode> entries() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        try (Stream<Path> files = Files.list(CryptoEventSpool.spoolDirectory())) {
            List<Path> paths = files.filter(path -> path.getFileName().toString().endsWith(".json"))
                    .collect(Collectors.toList());
            List<JsonNode> parsed = new ArrayList<>();
            for (Path path : paths) {
                parsed.add(mapper.readTree(path.toFile()));
            }
            return parsed;
        }
    }

    private JsonNode onlyEntry() throws IOException {
        List<JsonNode> entries = entries();
        assertEquals(1, entries.size());
        return entries.get(0);
    }
}
