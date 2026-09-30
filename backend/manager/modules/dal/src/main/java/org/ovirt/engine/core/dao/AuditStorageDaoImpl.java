package org.ovirt.engine.core.dao;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Named;
import javax.inject.Singleton;

/**
 * {@code AuditStorageDaoImpl} provides a concrete implementation of {@link AuditStorageDao}.
 */
@Named
@Singleton
public class AuditStorageDaoImpl extends BaseDao implements AuditStorageDao {

    /**
     * The tables the audit record protection tab backs up and restores.
     */
    static final List<String> EVENT_TABLES = Collections.unmodifiableList(Arrays.asList(
            "audit_log", //$NON-NLS-1$
            "event_map", //$NON-NLS-1$
            "event_notification_hist", //$NON-NLS-1$
            "event_subscriber")); //$NON-NLS-1$

    @Override
    public long getDatabaseSize() {
        Long size = getJdbcTemplate().queryForObject(
                "SELECT pg_database_size(current_database())", //$NON-NLS-1$
                Long.class);
        return size == null ? 0L : size;
    }

    @Override
    public Map<String, Long> getEventTableSizes() {
        Map<String, Long> sizes = new LinkedHashMap<>();
        for (String table : EVENT_TABLES) {
            // to_regclass keeps a missing table from failing the whole measurement.
            Long size = getJdbcTemplate().queryForObject(
                    "SELECT COALESCE(pg_total_relation_size(to_regclass(?)), 0)", //$NON-NLS-1$
                    Long.class,
                    "public." + table); //$NON-NLS-1$
            sizes.put(table, size == null ? 0L : size);
        }
        return sizes;
    }
}
