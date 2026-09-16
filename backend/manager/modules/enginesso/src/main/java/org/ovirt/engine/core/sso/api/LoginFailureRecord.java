package org.ovirt.engine.core.sso.api;

import java.time.Instant;

/**
 * What is known about one account's failed password attempts: how many have been counted, and
 * until when the account is locked because of them.
 */
public class LoginFailureRecord {

    private final int failureCount;
    private final Instant lockedUntil;

    public LoginFailureRecord(int failureCount, Instant lockedUntil) {
        this.failureCount = failureCount;
        this.lockedUntil = lockedUntil;
    }

    public int getFailureCount() {
        return failureCount;
    }

    /**
     * @return when the lock lifts, or null when the account is not locked
     */
    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public boolean isLocked() {
        return lockedUntil != null;
    }
}
