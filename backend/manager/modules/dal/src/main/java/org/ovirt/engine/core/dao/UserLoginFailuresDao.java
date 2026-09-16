package org.ovirt.engine.core.dao;

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
}
