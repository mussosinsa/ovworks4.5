package org.ovirt.engine.core.sso.service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.ovirt.engine.core.sso.api.LoginFailureRecord;

/**
 * In-process lockout tracker for privileged admin account password authentication.
 *
 * <p>One account is tracked here, so the map stays small and the lock is deliberately not written
 * down: an administrator locked out by a restart of the engine would be locked out of the repair
 * as well, and the account has to stay reachable when the database is not. Every other account is
 * tracked by {@link UserLoginLockoutService} instead.</p>
 */
public class AdminLoginLockoutService implements LoginLockout {

    static final class LockRecord {
        private int failureCount;
        private Instant lockedUntil;
    }

    private final Map<String, LockRecord> lockRecords = new ConcurrentHashMap<>();

    @Override
    public Instant getLockedUntil(String principalKey) {
        LockRecord record = lockRecords.get(principalKey);
        if (record == null) {
            return null;
        }
        synchronized (record) {
            return record.lockedUntil;
        }
    }

    @Override
    public LoginFailureRecord recordFailure(String principalKey, Instant now, int maxFailures,
            Duration lockDuration) {
        LockRecord record = lockRecords.computeIfAbsent(principalKey, key -> new LockRecord());
        synchronized (record) {
            if (record.lockedUntil != null) {
                if (record.lockedUntil.isAfter(now)) {
                    return new LoginFailureRecord(record.failureCount, record.lockedUntil);
                }
                // The lock has run out, so this failure starts a fresh count rather than landing
                // on top of the one that led to the lock and locking the account straight away.
                record.lockedUntil = null;
                record.failureCount = 0;
            }

            record.failureCount++;
            if (record.failureCount >= maxFailures) {
                record.lockedUntil = now.plus(lockDuration);
                return new LoginFailureRecord(record.failureCount, record.lockedUntil);
            }

            return new LoginFailureRecord(record.failureCount, null);
        }
    }

    @Override
    public void recordSuccess(String principalKey) {
        LockRecord record = lockRecords.get(principalKey);
        if (record == null) {
            return;
        }
        synchronized (record) {
            record.failureCount = 0;
            record.lockedUntil = null;
        }
    }
}
