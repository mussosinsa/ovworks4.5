/*
 * Copyright 새올정보기술 (OV-Works), 2026
 * SPDX-License-Identifier: Apache-2.0
 */
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
    private static final String USER_SERIAL = "ovworks00092";

    @Test
    void beforeTheLoginTheAdministratorsSerialOrAnyUsersSerialIsAccepted() {
        Set<String> users = Set.of(USER_SERIAL);
        assertNull(ClientSerialCheck.check(ADMIN_SERIAL, ADMIN_SERIAL, users));
        assertNull(ClientSerialCheck.check(USER_SERIAL, ADMIN_SERIAL, users));
        assertEquals(Refusal.INVALID, ClientSerialCheck.check("ovworks00093", ADMIN_SERIAL, users));
        assertEquals(Refusal.MISSING, ClientSerialCheck.check(null, ADMIN_SERIAL, users));
    }

    @Test
    void aUsersSerialIsAcceptedEvenWhenTheAdministratorsCannotBeRead() {
        Set<String> users = Set.of(USER_SERIAL);
        assertNull(ClientSerialCheck.check(USER_SERIAL, null, users));
        assertEquals(Refusal.INVALID, ClientSerialCheck.check("OTHER", null, users));
        assertEquals(Refusal.UNVERIFIABLE, ClientSerialCheck.check("OTHER", null, Set.of()));
    }

    @Test
    void atTheLoginAUserHasToPresentItsOwnSerial() {
        assertNull(ClientSerialCheck.checkUserSerial(USER_SERIAL, USER_SERIAL));
        assertEquals(Refusal.INVALID, ClientSerialCheck.checkUserSerial(ADMIN_SERIAL, USER_SERIAL));
        assertEquals(Refusal.INVALID, ClientSerialCheck.checkUserSerial("ovworks00093", USER_SERIAL));
        assertEquals(Refusal.UNVERIFIABLE, ClientSerialCheck.checkUserSerial(USER_SERIAL, null));
        assertEquals(Refusal.MISSING, ClientSerialCheck.checkUserSerial("", USER_SERIAL));
    }

    @Test
    void aUsersSerialIsOvworksAndItsSerialNumberTwelveToSixteenCharacters() {
        assertTrue(ClientSerialCheck.isAcceptableSerial("ovworks00001"));      // 12
        assertTrue(ClientSerialCheck.isAcceptableSerial("ovworks123456789"));  // 16
        assertFalse(ClientSerialCheck.isAcceptableSerial("ovworks0001"));      // 11
        assertFalse(ClientSerialCheck.isAcceptableSerial("ovworks1234567890")); // 17
        assertFalse(ClientSerialCheck.isAcceptableSerial("OVWORKS00001"));
        assertFalse(ClientSerialCheck.isAcceptableSerial("ovworks0000a"));
        assertFalse(ClientSerialCheck.isAcceptableSerial("xvworks00001"));
        assertFalse(ClientSerialCheck.isAcceptableSerial(null));
    }

    @Test
    void aListThatCannotBeOpenedWithTheDekAcceptsNoUserSerial(@TempDir Path dir) throws IOException {
        // No DEK was handed to this run: the sealed lines do not open, and nothing is accepted.
        Path file = dir.resolve("client-serials");
        Files.write(file, List.of("T1ZFTkMwMDI=", "not base64 !", ""));
        assertTrue(ClientSerialCheck.loadUserSerials(file).isEmpty());
        assertTrue(ClientSerialCheck.loadUserSerials(dir.resolve("missing")).isEmpty());
    }
}
