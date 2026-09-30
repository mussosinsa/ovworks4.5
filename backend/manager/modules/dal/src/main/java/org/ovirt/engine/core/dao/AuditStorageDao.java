package org.ovirt.engine.core.dao;

import java.util.Date;
import java.util.List;

/**
 * Reads how much of the engine database the audit records occupy. Only what the engine's own
 * database account may read is asked for: the file system under the database, its WAL and the
 * server settings are measured by the storage helper instead.
 */
public interface AuditStorageDao extends Dao {

    /**
     * How much room one event table takes.
     *
     * <p>Two figures, because a PostgreSQL table does not shrink when rows are deleted: the space
     * they took is kept for new rows to reuse. The physical size therefore says how much disk the
     * table holds, and the live size how much of it the rows still in the table need - which is
     * what falls when old records are removed, and what a limit on the records is measured against.</p>
     */
    final class EventTableUsage {
        /** Bytes a row carries beyond its columns: the tuple header and its line pointer. */
        static final int ROW_OVERHEAD_BYTES = 28;

        private final String table;
        private final long totalBytes;
        private final long liveBytes;
        private final long liveRows;

        public EventTableUsage(String table, long totalBytes, long liveBytes, long liveRows) {
            this.table = table;
            this.totalBytes = totalBytes;
            this.liveBytes = liveBytes;
            this.liveRows = liveRows;
        }

        /**
         * Estimates the live size from the planner statistics: the rows the table holds, each as wide
         * as its columns are on average plus the row overhead, with the indexes and TOAST in the
         * same proportion to the table as they are now. Falls back to the physical size when the
         * table has not been analysed yet, so an unknown estimate never reads as an empty table.
         */
        public static EventTableUsage estimate(String table, long totalBytes, long heapBytes, long liveRows,
                long averageRowWidth) {
            if (heapBytes <= 0 || averageRowWidth <= 0 || liveRows < 0) {
                return new EventTableUsage(table, totalBytes, totalBytes, Math.max(0, liveRows));
            }
            double liveHeap = (double) liveRows * (averageRowWidth + ROW_OVERHEAD_BYTES);
            long live = Math.round(liveHeap * totalBytes / heapBytes);
            return new EventTableUsage(table, totalBytes, Math.min(totalBytes, live), liveRows);
        }

        public String getTable() {
            return table;
        }

        public long getTotalBytes() {
            return totalBytes;
        }

        public long getLiveBytes() {
            return liveBytes;
        }

        public long getLiveRows() {
            return liveRows;
        }
    }

    /**
     * @return the size in bytes of the engine database, tables, indexes and TOAST included
     */
    long getDatabaseSize();

    /**
     * @return the usage of each event table, in the order the tables are backed up
     */
    List<EventTableUsage> getEventTableUsage();

    /**
     * @return the time of the audit record that has {@code olderRecords} records older than it,
     *         so that removing everything before it removes that many; {@code null} when there are
     *         no more records than that
     */
    Date getAuditLogTimeAfterOldest(long olderRecords);

    /**
     * @return how many audit records were logged before {@code cutoff}
     */
    long countAuditLogOlderThan(Date cutoff);
}
