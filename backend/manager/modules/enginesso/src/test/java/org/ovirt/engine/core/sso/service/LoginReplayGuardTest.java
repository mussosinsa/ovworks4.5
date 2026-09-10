package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.sso.service.LoginReplayGuard.LoginEnvelopeException;
import org.ovirt.engine.core.sso.service.LoginReplayGuard.NonceStore;

/**
 * What a recorded credential runs into when it is presented a second time.
 */
class LoginReplayGuardTest {

    private static final String PASSWORD = "Kf7#mQx2$Lpv";
    private static final int WINDOW = 120;
    private static final Instant NOW = Instant.ofEpochSecond(1_800_000_000L);

    private final NonceStore nonces = new NonceStore();

    private static String wrapped(Instant issuedAt, String nonce, String credential) {
        return "ovirt-login:v1:" + issuedAt.getEpochSecond() + ":" + nonce + ":" + credential;
    }

    private String unwrap(String decrypted, Instant now) throws LoginEnvelopeException {
        return LoginReplayGuard.unwrap(decrypted, false, WINDOW, now, nonces);
    }

    @Test
    void acceptsACredentialPresentedForTheFirstTime() throws Exception {
        assertEquals(PASSWORD, unwrap(wrapped(NOW, "n1", PASSWORD), NOW));
    }

    @Test
    void refusesTheSameCredentialPresentedAgain() throws Exception {
        String recorded = wrapped(NOW, "n1", PASSWORD);
        unwrap(recorded, NOW);

        // the recording is replayed a second later, well inside the window
        assertThrows(LoginEnvelopeException.class, () -> unwrap(recorded, NOW.plusSeconds(1)));
    }

    @Test
    void refusesACredentialReplayedAfterTheClientClosed() {
        String recorded = wrapped(NOW, "n1", PASSWORD);

        assertThrows(LoginEnvelopeException.class, () -> unwrap(recorded, NOW.plusSeconds(WINDOW + 1)));
    }

    @Test
    void refusesACredentialFromTooFarAhead() {
        String fromTheFuture = wrapped(NOW.plusSeconds(WINDOW + 1), "n1", PASSWORD);

        assertThrows(LoginEnvelopeException.class, () -> unwrap(fromTheFuture, NOW));
    }

    @Test
    void allowsClocksToDifferWithinTheWindow() throws Exception {
        assertEquals(PASSWORD, unwrap(wrapped(NOW.minusSeconds(WINDOW), "behind", PASSWORD), NOW));
        assertEquals(PASSWORD, unwrap(wrapped(NOW.plusSeconds(WINDOW), "ahead", PASSWORD), NOW));
    }

    @Test
    void acceptsEachLoginOfALoopThatWrapsAfresh() throws Exception {
        for (int i = 0; i < 10; i++) {
            Instant when = NOW.plusSeconds(i);
            assertEquals(PASSWORD, unwrap(wrapped(when, "nonce-" + i, PASSWORD), when));
        }
    }

    @Test
    void keepsACredentialThatContainsColons() throws Exception {
        String awkward = "a:b::c";

        assertEquals(awkward, unwrap(wrapped(NOW, "n1", awkward), NOW));
    }

    @Test
    void forgetsANonceOnceItIsTooOldToMatter() throws Exception {
        unwrap(wrapped(NOW, "n1", PASSWORD), NOW);

        // Past the window the timestamp check refuses the replay on its own, so there is nothing
        // left to remember - and the store must not grow forever holding it.
        unwrap(wrapped(NOW.plusSeconds(WINDOW + 10), "n2", PASSWORD), NOW.plusSeconds(WINDOW + 10));

        assertEquals(1, nonces.size());
    }

    /* An unwrapped credential: nothing in it tells one presentation from the next. */

    @Test
    void acceptsAnUnwrappedCredentialWhileClientsAreStillBeingUpdated() throws Exception {
        assertEquals(PASSWORD, LoginReplayGuard.unwrap(PASSWORD, false, WINDOW, NOW, nonces));
    }

    @Test
    void refusesAnUnwrappedCredentialOnceTheDeploymentRequiresOne() {
        assertThrows(LoginEnvelopeException.class,
                () -> LoginReplayGuard.unwrap(PASSWORD, true, WINDOW, NOW, nonces));
    }

    @Test
    void checksAWrappedCredentialWhetherOrNotOneIsRequired() throws Exception {
        String recorded = wrapped(NOW, "n1", PASSWORD);
        LoginReplayGuard.unwrap(recorded, false, WINDOW, NOW, nonces);

        assertThrows(LoginEnvelopeException.class,
                () -> LoginReplayGuard.unwrap(recorded, false, WINDOW, NOW, nonces));
    }

    /* A wrapper the server cannot read is never taken for a credential. */

    @Test
    void refusesAWrapperItCannotRead() {
        assertThrows(LoginEnvelopeException.class, () -> unwrap("ovirt-login:v1:not-a-time:n1:" + PASSWORD, NOW));
        assertThrows(LoginEnvelopeException.class, () -> unwrap("ovirt-login:v1:" + NOW.getEpochSecond(), NOW));
        assertThrows(LoginEnvelopeException.class,
                () -> unwrap("ovirt-login:v1:" + NOW.getEpochSecond() + "::" + PASSWORD, NOW));
    }

    @Test
    void refusesOnceThereIsNoRoomLeftToRememberNonces() {
        Instant rememberUntil = NOW.plusSeconds(WINDOW);
        for (int i = 0; i < LoginReplayGuard.MAX_REMEMBERED_NONCES; i++) {
            assertTrue(nonces.spend("filler-" + i, rememberUntil, NOW));
        }

        assertThrows(LoginEnvelopeException.class, () -> unwrap(wrapped(NOW, "one-too-many", PASSWORD), NOW));
    }
}
