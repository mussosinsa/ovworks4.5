package org.ovirt.engine.core.sso.service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-process lockout tracker for privileged admin account password authentication.
 */
public class AdminLoginLockoutService {

    static final class LockRecord {
        private int failureCount;
        private Instant lockedUntil;
    }

    public static final class FailureResult {
        private final int failureCount;
        private final boolean locked;
        private final Instant lockedUntil;

        FailureResult(int failureCount, boolean locked, Instant lockedUntil) {
            this.failureCount = failureCount;
            this.locked = locked;
            this.lockedUntil = lockedUntil;
        }

        public int getFailureCount() {
            return failureCount;
        }

        public boolean isLocked() {
            return locked;
        }

        public Instant getLockedUntil() {
            return lockedUntil;
        }
    }

    private final Map<String, LockRecord> lockRecords = new ConcurrentHashMap<>();

    public boolean isLocked(String principalKey, Instant now) {
        LockRecord record = lockRecords.get(principalKey);
        if (record == null) {
            return false;
        }

        synchronized (record) {
            if (record.lockedUntil != null && record.lockedUntil.isAfter(now)) {
                return true;
            }
            if (record.lockedUntil != null && !record.lockedUntil.isAfter(now)) {
                record.lockedUntil = null;
                record.failureCount = 0;
            }
            return false;
        }
    }

    public Instant getLockedUntil(String principalKey) {
        LockRecord record = lockRecords.get(principalKey);
        if (record == null) {
            return null;
        }
        synchronized (record) {
            return record.lockedUntil;
        }
    }

    public FailureResult recordFailure(String principalKey, Instant now, int maxFailures, Duration lockDuration) {
        LockRecord record = lockRecords.computeIfAbsent(principalKey, key -> new LockRecord());
        synchronized (record) {
            if (record.lockedUntil != null && record.lockedUntil.isAfter(now)) {
                return new FailureResult(record.failureCount, true, record.lockedUntil);
            }

            record.failureCount++;
            if (record.failureCount >= maxFailures) {
                record.lockedUntil = now.plus(lockDuration);
                return new FailureResult(record.failureCount, true, record.lockedUntil);
            }

            return new FailureResult(record.failureCount, false, null);
        }
    }

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
