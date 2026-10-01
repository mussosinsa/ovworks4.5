package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.sso.api.SsoSession;
import org.ovirt.engine.core.sso.service.LoginReplayGuard.LoginEnvelopeException;
import org.ovirt.engine.core.sso.service.LoginReplayGuard.NonceStore;
import org.ovirt.engine.core.sso.service.LoginReplayGuard.Reason;

/**
 * What a copy of a login page submission runs into, and the reason each refusal is recorded with.
 */
class LoginFormNonceTest {

    private static final String PASSWORD = "Kf7#mQx2$Lpv:with:colons";

    private static String wrapped(String nonce, String credential) {
        return "ovirt-login:v1:1800000000:" + nonce + ":" + credential;
    }

    @Test
    void theLoginPageLogsInOnceWithTheNonceItWasIssued() throws Exception {
        SsoSession session = new SsoSession();
        String nonce = LoginFormNonce.issue(session);

        assertEquals(PASSWORD, LoginFormNonce.unwrap(session, wrapped(nonce, PASSWORD)));
    }

    @Test
    void theSameSubmissionSentAgainIsRefused() throws Exception {
        // The user logs in, logs out, and a copy of the login request is sent again.
        SsoSession session = new SsoSession();
        String submission = wrapped(LoginFormNonce.issue(session), PASSWORD);
        LoginFormNonce.unwrap(session, submission);

        LoginEnvelopeException refusal =
                assertThrows(LoginEnvelopeException.class, () -> LoginFormNonce.unwrap(session, submission));
        assertEquals(Reason.FORM_NOT_ISSUED, refusal.getReason());
    }

    @Test
    void aSubmissionSentInAnotherSessionIsRefused() {
        // A copy replayed without the original cookie arrives in a session of its own, to which
        // the nonce was never issued.
        String submission = wrapped(LoginFormNonce.issue(new SsoSession()), PASSWORD);

        LoginEnvelopeException refusal = assertThrows(LoginEnvelopeException.class,
                () -> LoginFormNonce.unwrap(new SsoSession(), submission));
        assertEquals(Reason.FORM_NOT_ISSUED, refusal.getReason());
        assertEquals(Reason.FORM_NOT_ISSUED,
                assertThrows(LoginEnvelopeException.class, () -> LoginFormNonce.unwrap(null, submission))
                        .getReason());
    }

    @Test
    void aPasswordTheLoginPageDidNotWrapIsRefused() {
        LoginEnvelopeException refusal = assertThrows(LoginEnvelopeException.class,
                () -> LoginFormNonce.unwrap(new SsoSession(), PASSWORD));
        assertEquals(Reason.UNWRAPPED, refusal.getReason());
    }

    @Test
    void aWrapperThatCannotBeReadIsRefused() {
        LoginEnvelopeException refusal = assertThrows(LoginEnvelopeException.class,
                () -> LoginFormNonce.unwrap(new SsoSession(), "ovirt-login:v1:not-a-time"));
        assertEquals(Reason.UNREADABLE, refusal.getReason());
    }

    @Test
    void aFailedAttemptSpendsTheNonceAndTheNextRenderingIssuesAnother() throws Exception {
        SsoSession session = new SsoSession();
        String first = LoginFormNonce.issue(session);
        LoginFormNonce.unwrap(session, wrapped(first, "wrong password"));
        String second = LoginFormNonce.issue(session);

        assertNotEquals(first, second);
        assertEquals(PASSWORD, LoginFormNonce.unwrap(session, wrapped(second, PASSWORD)));
    }

    @Test
    void severalOpenLoginPagesEachLogInOnce() throws Exception {
        SsoSession session = new SsoSession();
        String firstTab = LoginFormNonce.issue(session);
        String secondTab = LoginFormNonce.issue(session);

        assertEquals(PASSWORD, LoginFormNonce.unwrap(session, wrapped(firstTab, PASSWORD)));
        assertEquals(PASSWORD, LoginFormNonce.unwrap(session, wrapped(secondTab, PASSWORD)));
    }

    @Test
    void onlyTheMostRecentRenderingsStayPending() {
        SsoSession session = new SsoSession();
        String oldest = LoginFormNonce.issue(session);
        for (int i = 0; i < LoginFormNonce.MAX_PENDING; i++) {
            LoginFormNonce.issue(session);
        }

        assertEquals(LoginFormNonce.MAX_PENDING, session.getPendingLoginFormNonces().size());
        assertThrows(LoginEnvelopeException.class, () -> LoginFormNonce.unwrap(session, wrapped(oldest, PASSWORD)));
    }

    @Test
    void issuedNoncesFitTheWrapper() {
        String nonce = LoginFormNonce.issue(new SsoSession());
        assertTrue(nonce.length() <= 64 && !nonce.contains(":"), nonce);
    }

    /* The reasons the REST client's refusals are recorded with. */

    @Test
    void restRefusalsNameTheirReason() throws Exception {
        NonceStore nonces = new NonceStore();
        Instant now = Instant.ofEpochSecond(1_800_000_000L);
        String recorded = "ovirt-login:v1:" + now.getEpochSecond() + ":n1:" + PASSWORD;
        LoginReplayGuard.unwrap(recorded, false, 120, now, nonces);

        assertEquals(Reason.ALREADY_USED, assertThrows(LoginEnvelopeException.class,
                () -> LoginReplayGuard.unwrap(recorded, false, 120, now.plusSeconds(1), nonces)).getReason());
        assertEquals(Reason.OUTSIDE_WINDOW, assertThrows(LoginEnvelopeException.class,
                () -> LoginReplayGuard.unwrap(recorded, false, 120, now.plusSeconds(121), nonces)).getReason());
        assertEquals(Reason.UNWRAPPED, assertThrows(LoginEnvelopeException.class,
                () -> LoginReplayGuard.unwrap(PASSWORD, true, 120, now, nonces)).getReason());
    }

    @Test
    void theAuditRecordNamesTheUserTheAddressTheChannelAndTheReason() {
        LoginEnvelopeException refusal = new LoginEnvelopeException(Reason.ALREADY_USED, "copy");

        assertEquals("LOGIN_REPLAY_BLOCKED user=admin@internal sourceIp=192.168.20.31 channel=API"
                        + " reason=ALREADY_USED",
                LoginReplayAudit.describe("admin@internal", "192.168.20.31", LoginReplayAudit.Channel.API, refusal));
        assertTrue(LoginReplayAudit.describe(null, "10.0.0.1", LoginReplayAudit.Channel.LOGIN_PAGE, refusal)
                .startsWith("LOGIN_REPLAY_BLOCKED user=N/A "));
        assertEquals("USER_VDC_LOGIN_REPLAY_BLOCKED", LoginReplayAudit.AUDIT_LOG_TYPE);
    }
}
