package org.ovirt.engine.core.uutils.security;

import java.time.Instant;

/**
 * One entry of a user password history: the encoded hash of a password that was used in
 * the past and the moment it was set.
 */
public class PasswordHistoryEntry {

    private final String encodedHash;
    private final Instant changeDate;

    public PasswordHistoryEntry(String encodedHash, Instant changeDate) {
        this.encodedHash = encodedHash;
        this.changeDate = changeDate;
    }

    public String getEncodedHash() {
        return encodedHash;
    }

    public Instant getChangeDate() {
        return changeDate;
    }
}
