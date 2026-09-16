package org.ovirt.engine.core.sso.service;

import java.time.Duration;
import java.time.Instant;

import org.ovirt.engine.core.sso.api.LoginFailureRecord;
import org.ovirt.engine.core.sso.db.SsoDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Lockout tracker for every account other than the protected administrator, kept in the database.
 *
 * <p>There can be as many of these accounts as the installation has users, and a lock on one of
 * them is something an administrator is expected to be able to see the end of and to lift, so the
 * count is written down: it survives a restart of the engine, reads the same on every node, and
 * the user list can clear it.</p>
 *
 * <p>The database is not allowed to decide who gets in. A failure that cannot be counted is
 * reported and dropped, and an account whose record cannot be read is treated as not locked -
 * losing the database must not lock every user out of the installation at once. The password is
 * still checked in both cases; only the counting is skipped.</p>
 */
public class UserLoginLockoutService implements LoginLockout {

    private static final Logger log = LoggerFactory.getLogger(UserLoginLockoutService.class);

    private final SsoDao ssoDao;

    public UserLoginLockoutService(SsoDao ssoDao) {
        this.ssoDao = ssoDao;
    }

    @Override
    public Instant getLockedUntil(String principalKey) {
        try {
            LoginFailureRecord record = ssoDao.getLoginFailures(principalKey);
            return record == null ? null : record.getLockedUntil();
        } catch (RuntimeException ex) {
            log.error("Unable to read the lock of '{}'; the account is treated as not locked", principalKey, ex);
            return null;
        }
    }

    @Override
    public boolean releaseIfExpired(String principalKey, Instant now) {
        try {
            return ssoDao.releaseExpiredLock(principalKey, now);
        } catch (RuntimeException ex) {
            log.error("Unable to release the expired lock of '{}'", principalKey, ex);
            return false;
        }
    }

    @Override
    public LoginFailureRecord recordFailure(String principalKey, Instant now, int maxFailures,
            Duration lockDuration) {
        try {
            return ssoDao.recordLoginFailure(principalKey, loginNameOf(principalKey), now, maxFailures, lockDuration);
        } catch (RuntimeException ex) {
            log.error("Unable to count the failed login of '{}'; the attempt is not counted", principalKey, ex);
            return new LoginFailureRecord(0, null);
        }
    }

    @Override
    public void recordSuccess(String principalKey) {
        try {
            ssoDao.clearLoginFailures(principalKey);
        } catch (RuntimeException ex) {
            log.error("Unable to clear the login failures of '{}'", principalKey, ex);
        }
    }

    /**
     * The name the account logs in with, taken back out of the principal key.
     *
     * <p>The key is what {@code AuthenticationService.principalKey} made of a name and a profile,
     * so the profile is what follows the last '@' and everything before it is the name - a name
     * that contains an '@' of its own included.</p>
     */
    static String loginNameOf(String principalKey) {
        int profileSeparator = principalKey.lastIndexOf('@');
        return profileSeparator <= 0 ? principalKey : principalKey.substring(0, profileSeparator);
    }
}
