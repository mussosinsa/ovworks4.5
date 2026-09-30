package org.ovirt.engine.core.dao;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

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

    private static final String EVENT_TABLE_USAGE =
            "SELECT COALESCE(pg_total_relation_size(c.oid), 0), " //$NON-NLS-1$
                    + "COALESCE(pg_relation_size(c.oid), 0), " //$NON-NLS-1$
                    + "COALESCE(s.n_live_tup, 0), " //$NON-NLS-1$
                    + "COALESCE((SELECT SUM(st.avg_width) FROM pg_stats st " //$NON-NLS-1$
                    + "WHERE st.schemaname = n.nspname AND st.tablename = c.relname), 0) " //$NON-NLS-1$
                    + "FROM pg_class c " //$NON-NLS-1$
                    + "JOIN pg_namespace n ON n.oid = c.relnamespace " //$NON-NLS-1$
                    + "LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid " //$NON-NLS-1$
                    + "WHERE n.nspname = 'public' AND c.relname = ? AND c.relkind = 'r'"; //$NON-NLS-1$

    @Override
    public long getDatabaseSize() {
        Long size = getJdbcTemplate().queryForObject(
                "SELECT pg_database_size(current_database())", //$NON-NLS-1$
                Long.class);
        return size == null ? 0L : size;
    }

    @Override
    public List<EventTableUsage> getEventTableUsage() {
        List<EventTableUsage> usages = new ArrayList<>();
        for (String table : EVENT_TABLES) {
            // A missing table yields no row rather than failing the whole measurement.
            List<EventTableUsage> rows = getJdbcTemplate().query(EVENT_TABLE_USAGE,
                    (rs, rowNum) -> EventTableUsage.estimate(table, rs.getLong(1), rs.getLong(2), rs.getLong(3),
                            rs.getLong(4)),
                    table);
            usages.add(rows.isEmpty() ? new EventTableUsage(table, 0, 0, 0) : rows.get(0));
        }
        return usages;
    }

    @Override
    public Date getAuditLogTimeAfterOldest(long olderRecords) {
        // Walks idx_audit_log_log_time from its start, so it reads only the records it skips.
        List<Timestamp> times = getJdbcTemplate().queryForList(
                "SELECT log_time FROM audit_log ORDER BY log_time ASC OFFSET ? LIMIT 1", //$NON-NLS-1$
                Timestamp.class,
                Math.max(0, olderRecords));
        return times.isEmpty() || times.get(0) == null ? null : new Date(times.get(0).getTime());
    }

    @Override
    public long countAuditLogOlderThan(Date cutoff) {
        Long count = getJdbcTemplate().queryForObject(
                "SELECT count(*) FROM audit_log WHERE log_time < ?", //$NON-NLS-1$
                Long.class,
                new Timestamp(cutoff.getTime()));
        return count == null ? 0L : count;
    }
}
