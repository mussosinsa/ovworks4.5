package org.ovirt.engine.core.dao;

import java.util.Date;
import java.util.List;

/**
 * {@code UserLoginFailuresDao} lifts the lock that repeated password failures put on an account.
 *
 * <p>The failures themselves are counted by the login path in the SSO module, which writes the
 * table directly. What the engine needs is the other end of it: an administrator asking, from the
 * user list, for an account to be let back in before its lock runs out.</p>
 */
public interface UserLoginFailuresDao extends Dao {

    /**
     * Forgets the failures counted against every account carrying this login name, and with them
     * the lock they led to.
     *
     * @param loginName the name the account logs in with, lowercase
     */
    void clearByLoginName(String loginName);

    /**
     * Releases every lock whose configured period has run out.
     *
     * <p>The engine releases a lock at the moment it expires rather than waiting for the account
     * to try to log in again, so that the release is recorded in the audit log when it happens and
     * an account nobody comes back to is not left looking locked. Releasing and reporting are the
     * one statement, so each lock is released - and reported - exactly once.</p>
     *
     * @param now the moment a lock is measured against
     * @return the principals whose locks this call released, as 'name@profile'
     */
    List<String> releaseExpired(Date now);
}
