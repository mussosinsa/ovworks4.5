package org.ovirt.engine.core.dao;

import java.util.Date;
import java.util.List;

import org.ovirt.engine.core.common.businessentities.aaa.UserPasswordHistoryEntry;

/**
 * Access to the password history that backs the password reuse policies.
 */
public interface UserPasswordHistoryDao extends Dao {

    /**
     * @param principal the normalized 'name@realm' key of the account
     * @param limit maximum number of entries to read, most recent first
     */
    List<UserPasswordHistoryEntry> getByPrincipal(String principal, int limit);

    void save(UserPasswordHistoryEntry entry);

    /**
     * Removes the entries that are both older than the given threshold and outside the
     * newest {@code keep} entries, so a history can not grow without bound.
     */
    void cleanup(String principal, Date threshold, int keep);
}
