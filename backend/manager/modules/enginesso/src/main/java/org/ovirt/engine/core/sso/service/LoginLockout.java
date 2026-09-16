package org.ovirt.engine.core.sso.service;

import java.time.Duration;
import java.time.Instant;

import org.ovirt.engine.core.sso.api.LoginFailureRecord;

/**
 * Where failed password attempts are counted and the lock they lead to is kept.
 *
 * <p>The protected administrator and everybody else are counted the same way but not in the same
 * place, which is what this exists for: the administrator's lock is held in memory so that the
 * account stays reachable while the database is not, and every other account's lock is held in the
 * database so that it survives a restart, reads the same on every node, and can be lifted from the
 * user list.</p>
 *
 * <p>The principal key is the one {@code AuthenticationService.principalKey} builds.</p>
 */
public interface LoginLockout {

    /**
     * @return when the recorded lock lifts, or null when none is recorded. An expired lock is
     *         still reported here, so that the caller can tell an account that has just come out
     *         of one from an account that was never locked.
     */
    Instant getLockedUntil(String principalKey);

    /**
     * Releases the account's lock if its period has run out, and says whether this call is the one
     * that released it.
     *
     * <p>Checking and releasing are one step so that the release is reported once: the engine
     * releases expired locks on a timer as well, and two callers arriving together must not both
     * announce the same release.</p>
     *
     * @return true when this call released a lock that had run out, false when there was no lock,
     *         when it has not run out yet, or when somebody else released it first
     */
    boolean releaseIfExpired(String principalKey, Instant now);

    /**
     * Counts one failed password attempt, locking the account for {@code lockDuration} once
     * {@code maxFailures} of them have been counted. A lock already in force is neither extended
     * nor re-counted.
     */
    LoginFailureRecord recordFailure(String principalKey, Instant now, int maxFailures, Duration lockDuration);

    /**
     * Forgets everything counted against the account, which is what a successful login and an
     * expired lock both amount to.
     */
    void recordSuccess(String principalKey);
}
