package org.ovirt.engine.core.sso.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Deque;
import java.util.Iterator;

import org.ovirt.engine.core.sso.api.SsoSession;
import org.ovirt.engine.core.sso.service.LoginReplayGuard.LoginEnvelopeException;
import org.ovirt.engine.core.sso.service.LoginReplayGuard.Reason;
import org.ovirt.engine.core.sso.utils.LoginEnvelope;
import org.ovirt.engine.core.uutils.crypto.ApprovedRandom;

/**
 * Makes each rendering of the login page good for one login, and no more.
 *
 * <p>The page encrypts the password before it is sent, which hides it but does not stop a copy of
 * the request being sent again: the server cannot tell a ciphertext it has just been handed from
 * the same one handed to it before, so a captured login was a login for as long as the password
 * stood - after the user had logged out as much as before.</p>
 *
 * <p>A REST client stops that by writing the time and a nonce of its own into the encryption, and
 * {@link LoginReplayGuard} checks both. A browser cannot be held to the time: its clock is the
 * user's, and a page left open for a few minutes is not a replay. So the nonce comes from the server
 * instead. Each time the page is rendered a nonce is issued to the SSO session and written into
 * the page; the page encrypts it together with the password, in the same wrapper a REST client
 * uses; and the login consumes it. A copy of the request names a nonce that is no longer pending -
 * spent by the login it was copied from, or never issued to the session presenting it - and is
 * refused, whenever it is sent.</p>
 *
 * <p>A few nonces are kept pending at once, so that a second tab, or the page rendered again after
 * a failed attempt, does not make the first unusable.</p>
 */
public final class LoginFormNonce {

    /** How many renderings of the login page can be pending at once. */
    static final int MAX_PENDING = 5;

    private static final SecureRandom RANDOM = ApprovedRandom.get();

    private LoginFormNonce() {
    }

    /**
     * Issues a nonce for one rendering of the login page.
     *
     * @return the nonce the page writes into the credential it encrypts
     */
    public static String issue(SsoSession ssoSession) {
        byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Deque<String> pending = ssoSession.getPendingLoginFormNonces();
        synchronized (pending) {
            while (pending.size() >= MAX_PENDING) {
                pending.removeFirst();
            }
            pending.addLast(nonce);
        }
        return nonce;
    }

    /**
     * Checks the decrypted password the login page sent and returns the password inside it.
     *
     * <p>The nonce is consumed whether the login then succeeds or not: it is good for one attempt.
     * The timestamp the page wrote is not checked - it is the server's own time at rendering, and
     * a page may sit open for as long as the user likes.</p>
     *
     * @throws LoginEnvelopeException when the password is not wrapped, the wrapper cannot be read,
     *         or its nonce is not one pending for this session
     */
    public static String unwrap(SsoSession ssoSession, String decrypted) throws LoginEnvelopeException {
        if (!LoginEnvelope.isWrapped(decrypted)) {
            // The login page always wraps. A form that does not is not the login page.
            throw new LoginEnvelopeException(Reason.UNWRAPPED,
                    "the login form credential carries no replay protection");
        }
        LoginEnvelope envelope;
        try {
            envelope = LoginEnvelope.parse(decrypted);
        } catch (IllegalArgumentException e) {
            throw new LoginEnvelopeException(Reason.UNREADABLE, "the replay protection cannot be read", e);
        }
        if (ssoSession == null || !consume(ssoSession.getPendingLoginFormNonces(), envelope.getNonce())) {
            throw new LoginEnvelopeException(Reason.FORM_NOT_ISSUED,
                    "the login form this credential claims to come from was not issued to this session,"
                            + " or has been used");
        }
        return envelope.getCredential();
    }

    private static boolean consume(Deque<String> pending, String nonce) {
        synchronized (pending) {
            Iterator<String> nonces = pending.iterator();
            while (nonces.hasNext()) {
                if (constantTimeEquals(nonces.next(), nonce)) {
                    nonces.remove();
                    return true;
                }
            }
            return false;
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }
}
