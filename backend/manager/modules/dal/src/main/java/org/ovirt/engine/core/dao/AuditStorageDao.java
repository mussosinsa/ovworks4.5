package org.ovirt.engine.core.dao;

import java.util.Map;

/**
 * Reads how much of the engine database the audit records occupy. Only what the engine's own
 * database account may read is asked for: the file system under the database, its WAL and the
 * server settings are measured by the storage helper instead.
 */
public interface AuditStorageDao extends Dao {

    /**
     * @return the size in bytes of the engine database, tables, indexes and TOAST included
     */
    long getDatabaseSize();

    /**
     * @return the total size in bytes of each event table, keyed by table name, in the order the
     *         tables are backed up
     */
    Map<String, Long> getEventTableSizes();
}
