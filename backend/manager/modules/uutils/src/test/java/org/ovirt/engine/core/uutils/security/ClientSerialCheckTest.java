package org.ovirt.engine.core.uutils.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck.Refusal;

public class ClientSerialCheckTest {

    private static final String SERIAL = "TERMINAL-0001";

    @Test
    void letsTheRegisteredSerialIn() {
        assertNull(ClientSerialCheck.check(SERIAL, SERIAL));
    }

    @Test
    void tellsAMissingHeaderFromAWrongOne() {
        assertEquals(Refusal.MISSING, ClientSerialCheck.check(null, SERIAL));
        assertEquals(Refusal.MISSING, ClientSerialCheck.check("", SERIAL));
        assertEquals(Refusal.INVALID, ClientSerialCheck.check("TERMINAL-0002", SERIAL));
        assertEquals(Refusal.INVALID, ClientSerialCheck.check(SERIAL + " ", SERIAL));
    }

    @Test
    void letsNothingInWhenTheRegisteredSerialCannotBeRead() {
        // An empty registered serial must not turn into "anything matches".
        assertEquals(Refusal.UNVERIFIABLE, ClientSerialCheck.check(SERIAL, null));
        assertEquals(Refusal.UNVERIFIABLE, ClientSerialCheck.check(SERIAL, ""));
        assertEquals(Refusal.MISSING, ClientSerialCheck.check(null, null));
    }

    @Test
    void theDescriptionSaysWhereAndWhyButNeverWhatWasPresented() {
        String description = ClientSerialCheck.describe("/ovirt-engine/sso/oauth/token", Refusal.INVALID);

        assertTrue(description.startsWith("/ovirt-engine/sso/oauth/token presented "), description);
        assertTrue(description.contains("does not match"), description);
        assertFalse(description.contains(SERIAL), description);
    }

    @Test
    void oneSourceIsRecordedOnceAMinutePerPlaceAndReason() {
        AtomicLong now = new AtomicLong(1_000_000L);
        ClientSerialCheck check = new ClientSerialCheck(now::get);

        assertTrue(check.isDue("10.0.0.5", "/ovirt-engine/", Refusal.MISSING));
        assertFalse(check.isDue("10.0.0.5", "/ovirt-engine/", Refusal.MISSING));
        // Another source, place or reason is news of its own.
        assertTrue(check.isDue("10.0.0.6", "/ovirt-engine/", Refusal.MISSING));
        assertTrue(check.isDue("10.0.0.5", "/ovirt-engine/sso/oauth/token", Refusal.MISSING));
        assertTrue(check.isDue("10.0.0.5", "/ovirt-engine/", Refusal.INVALID));

        now.addAndGet(ClientSerialCheck.REPORT_INTERVAL_MILLIS - 1);
        assertFalse(check.isDue("10.0.0.5", "/ovirt-engine/", Refusal.MISSING));
        now.addAndGet(1);
        assertTrue(check.isDue("10.0.0.5", "/ovirt-engine/", Refusal.MISSING));
    }

    @Test
    void manySourcesDoNotGrowTheMemoryWithoutBound() {
        ClientSerialCheck check = new ClientSerialCheck(() -> 0L);
        for (int i = 0; i < ClientSerialCheck.MAX_REMEMBERED + 5; i++) {
            assertTrue(check.isDue("10.0." + i, "/", Refusal.MISSING));
        }
    }

    @Test
    void theEngineHostItselfIsNotATerminal() throws Exception {
        assertTrue(ClientSerialCheck.isThisHost("127.0.0.1"));
        assertTrue(ClientSerialCheck.isThisHost("127.0.0.2"));
        assertTrue(ClientSerialCheck.isThisHost("::1"));
        // Every address this host's own interfaces carry.
        for (NetworkInterface networkInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            for (InetAddress address : Collections.list(networkInterface.getInetAddresses())) {
                assertTrue(ClientSerialCheck.isThisHost(address.getHostAddress()), address.getHostAddress());
            }
        }
    }

    @Test
    void anotherMachineOrANameIsNot() {
        assertFalse(ClientSerialCheck.isThisHost(null));
        assertFalse(ClientSerialCheck.isThisHost(""));
        assertFalse(ClientSerialCheck.isThisHost("192.0.2.10"));
        assertFalse(ClientSerialCheck.isThisHost("2001:db8::10"));
        // Names are never looked up.
        assertFalse(ClientSerialCheck.isThisHost("localhost"));
        assertFalse(ClientSerialCheck.isThisHost("127.0.0.1.example.com"));
    }

    // --- administrators' serial (config.json) and users' own serials ---

    private static final String ADMIN_SERIAL = "ADMIN-0001";
    private static final String USER_SERIAL = "USER-0092";

    @Test
    void beforeTheLoginTheAdministratorsSerialOrAnyUsersSerialIsAccepted() {
        Set<String> users = Set.of(ClientSerialCheck.digest(USER_SERIAL));
        assertNull(ClientSerialCheck.check(ADMIN_SERIAL, ADMIN_SERIAL, users));
        assertNull(ClientSerialCheck.check(USER_SERIAL, ADMIN_SERIAL, users));
        assertEquals(Refusal.INVALID, ClientSerialCheck.check("OTHER", ADMIN_SERIAL, users));
        assertEquals(Refusal.MISSING, ClientSerialCheck.check(null, ADMIN_SERIAL, users));
    }

    @Test
    void aUsersSerialIsAcceptedEvenWhenTheAdministratorsCannotBeRead() {
        Set<String> users = Set.of(ClientSerialCheck.digest(USER_SERIAL));
        assertNull(ClientSerialCheck.check(USER_SERIAL, null, users));
        assertEquals(Refusal.INVALID, ClientSerialCheck.check("OTHER", null, users));
        assertEquals(Refusal.UNVERIFIABLE, ClientSerialCheck.check("OTHER", null, Set.of()));
    }

    @Test
    void atTheLoginAUserHasToPresentItsOwnSerial() {
        String registered = ClientSerialCheck.digest(USER_SERIAL);
        assertNull(ClientSerialCheck.checkUserSerial(USER_SERIAL, registered));
        assertEquals(Refusal.INVALID, ClientSerialCheck.checkUserSerial(ADMIN_SERIAL, registered));
        assertEquals(Refusal.INVALID, ClientSerialCheck.checkUserSerial("USER-0093", registered));
        assertEquals(Refusal.UNVERIFIABLE, ClientSerialCheck.checkUserSerial(USER_SERIAL, null));
        assertEquals(Refusal.MISSING, ClientSerialCheck.checkUserSerial("", registered));
    }

    @Test
    void aSerialIsKeptAsItsSha256Digest() {
        assertEquals("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                ClientSerialCheck.digest("test"));
    }

    @Test
    void onlyASerialAHeaderCanCarryIsAccepted() {
        assertTrue(ClientSerialCheck.isAcceptableSerial("SN-2026.10:A_01"));
        assertFalse(ClientSerialCheck.isAcceptableSerial("with space"));
        assertFalse(ClientSerialCheck.isAcceptableSerial(""));
        assertFalse(ClientSerialCheck.isAcceptableSerial("x".repeat(129)));
    }

    @Test
    void theRegisteredDigestsAreReadFromTheEnginesList(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("client-serials");
        String digest = ClientSerialCheck.digest(USER_SERIAL);
        Files.write(file, List.of(digest, "not-a-digest", ""));
        assertEquals(Set.of(digest), ClientSerialCheck.loadUserSerialDigests(file));
        assertTrue(ClientSerialCheck.loadUserSerialDigests(dir.resolve("missing")).isEmpty());
    }
}
