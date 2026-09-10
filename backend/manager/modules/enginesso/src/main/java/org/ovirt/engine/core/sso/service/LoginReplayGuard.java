package org.ovirt.engine.core.sso.service;

import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.sso.db.SsoDao;
import org.ovirt.engine.core.sso.utils.LoginEnvelope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decides whether a credential the server has just decrypted is being presented for the first time,
 * or is a copy of one presented before.
 *
 * <p>A wrapped credential says when it was written and carries a value its client will not write
 * again, so a copy of it fails one of two checks: it is either too old, or its nonce has already
 * been spent. A copy taken now and replayed in a minute fails the second; one replayed after the
 * client has closed fails the first. See {@link LoginEnvelope} for why encryption alone leaves
 * both open.</p>
 *
 * <p>An unwrapped credential cannot be checked at all - there is nothing in it that distinguishes
 * one presentation from the next. Whether those are still accepted is what
 * {@code ENGINE_SSO_LOGIN_REQUIRE_FRESH_CREDENTIALS} decides, and it starts off allowing them so
 * that upgrading the engine does not lock out clients that have not been updated yet. Note what
 * this does and does not mean: a client that wraps its credentials is protected the moment the
 * engine is upgraded, whatever the option says, because every copy an attacker can take of that
 * client's requests is a wrapped one. The option closes the remaining door - a deployment that has
 * finished updating its clients can refuse the unwrapped form outright.</p>
 *
 * <p>None of this helps against someone who can read the request and replay it within the window,
 * which is to say someone sitting on the client's own machine as it runs. What it ends is the far
 * easier attack: keep a copy, come back later.</p>
 */
public final class LoginReplayGuard {

    /** Refuse credentials that carry no wrapper at all. */
    static final String REQUIRE_OPTION = "ENGINE_SSO_LOGIN_REQUIRE_FRESH_CREDENTIALS"; //$NON-NLS-1$

    /** How far from now a wrapper's timestamp may be, in seconds, in either direction. */
    static final String WINDOW_OPTION = "ENGINE_SSO_LOGIN_FRESHNESS_SECONDS"; //$NON-NLS-1$

    static final int DEFAULT_WINDOW_SECONDS = 120;

    /**
     * A ceiling on remembered nonces, so that a flood of logins cannot grow the map without bound.
     * Entries are dropped as they age out, so this is only ever reached by a rate of logins that is
     * itself a problem: at the default window it takes hundreds of logins per second, each costing
     * the server an RSA decryption.
     */
    static final int MAX_REMEMBERED_NONCES = 100_000;

    private static final Logger log = LoggerFactory.getLogger(LoginReplayGuard.class);

    private static final SsoDao SSO_DAO = new SsoDao();

    private static final NonceStore SPENT_NONCES = new NonceStore();

    private LoginReplayGuard() {
    }

    /**
     * Checks the decrypted text and returns the credential inside it.
     *
     * @param decrypted what came out of the decryption
     * @return the credential to authenticate with
     * @throws LoginEnvelopeException when the credential must not be used: its wrapper is stale,
     *         its nonce has been spent, its wrapper is unreadable, or it has no wrapper and this
     *         deployment requires one
     */
    public static String unwrap(String decrypted) throws LoginEnvelopeException {
        return unwrap(decrypted, requireWrappedCredentials(), windowSeconds(), Instant.now(), SPENT_NONCES);
    }

    /** The decision itself, with everything it depends on passed in so that it can be exercised. */
    static String unwrap(
            String decrypted,
            boolean requireWrapped,
            int windowSeconds,
            Instant now,
            NonceStore spentNonces) throws LoginEnvelopeException {

        if (!LoginEnvelope.isWrapped(decrypted)) {
            if (requireWrapped) {
                log.warn("Refusing a credential that carries no replay protection; the client that sent it"
                        + " has not been updated, or {} should be off.", REQUIRE_OPTION);
                throw new LoginEnvelopeException("the credential carries no replay protection");
            }
            return decrypted;
        }

        LoginEnvelope envelope;
        try {
            envelope = LoginEnvelope.parse(decrypted);
        } catch (IllegalArgumentException e) {
            log.warn("Refusing a credential whose replay protection cannot be read: {}", e.getMessage());
            throw new LoginEnvelopeException("the replay protection cannot be read", e);
        }

        long ageSeconds = now.getEpochSecond() - envelope.getIssuedAtEpochSecond();
        if (Math.abs(ageSeconds) > windowSeconds) {
            // Both directions: a timestamp far in the future is as much a sign of a clock that
            // cannot be trusted as one far in the past, and neither tells us the request is fresh.
            log.warn("Refusing a credential written {} seconds from now, outside the {} second window."
                    + " It is a replayed copy, or the clocks differ.", ageSeconds, windowSeconds);
            throw new LoginEnvelopeException("the credential is outside the freshness window");
        }

        // Kept only until the timestamp check would reject it anyway, which is exactly as long as
        // remembering it is worth anything.
        Instant rememberUntil = Instant.ofEpochSecond(envelope.getIssuedAtEpochSecond() + windowSeconds);
        if (!spentNonces.spend(envelope.getNonce(), rememberUntil, now)) {
            log.warn("Refusing a credential whose nonce has already been used. It is a replayed copy.");
            throw new LoginEnvelopeException("the credential has already been used");
        }

        return envelope.getCredential();
    }

    private static boolean requireWrappedCredentials() {
        try {
            return Boolean.parseBoolean(StringUtils.trimToEmpty(SSO_DAO.getVdcOptionValue(REQUIRE_OPTION)));
        } catch (RuntimeException e) {
            // Reading the option failed, so nothing is known about what this deployment wants.
            // Wrapped credentials are still checked; only the refusal of unwrapped ones is dropped,
            // which is the choice that cannot lock everybody out over a database hiccup.
            log.warn("Unable to read {}; not requiring replay protection on this request", REQUIRE_OPTION);
            log.debug("Exception", e);
            return false;
        }
    }

    private static int windowSeconds() {
        try {
            int seconds = Integer.parseInt(StringUtils.trimToEmpty(SSO_DAO.getVdcOptionValue(WINDOW_OPTION)));
            return seconds > 0 ? seconds : DEFAULT_WINDOW_SECONDS;
        } catch (RuntimeException e) {
            return DEFAULT_WINDOW_SECONDS;
        }
    }

    /** The nonces spent so far, each held until it is too old to be worth holding. */
    static class NonceStore {

        private final ConcurrentMap<String, Instant> spent = new ConcurrentHashMap<>();

        /**
         * @return true when the nonce had not been spent and now is; false when it was already
         *         spent, or when there is no room left to remember it - in which case the caller
         *         refuses the credential, since a nonce that is not remembered is not protecting
         *         anything
         */
        synchronized boolean spend(String nonce, Instant rememberUntil, Instant now) {
            dropExpired(now);
            if (spent.size() >= MAX_REMEMBERED_NONCES) {
                log.error("Refusing a login: {} nonces are being remembered, which is the limit."
                        + " Logins are arriving faster than this deployment expects.", spent.size());
                return false;
            }
            return spent.putIfAbsent(nonce, rememberUntil) == null;
        }

        private void dropExpired(Instant now) {
            Iterator<Map.Entry<String, Instant>> entries = spent.entrySet().iterator();
            while (entries.hasNext()) {
                if (!entries.next().getValue().isAfter(now)) {
                    entries.remove();
                }
            }
        }

        int size() {
            return spent.size();
        }
    }

    /** Raised when a decrypted credential must not be used. */
    public static class LoginEnvelopeException extends GeneralSecurityException {

        private static final long serialVersionUID = 1L;

        LoginEnvelopeException(String message) {
            super(message);
        }

        LoginEnvelopeException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
