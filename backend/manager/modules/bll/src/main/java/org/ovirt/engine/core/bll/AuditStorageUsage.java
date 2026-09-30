package org.ovirt.engine.core.bll;

import org.ovirt.engine.core.bll.AuditStorageThresholds.Level;

/**
 * One measured store of audit records: how full it is, and what that level means.
 */
public final class AuditStorageUsage {

    /**
     * What was measured. Only the targets that have a capacity are given a level; the others are
     * shown for the administrator to follow their growth.
     */
    public enum Target {
        DB_FILESYSTEM("DB 데이터 파일시스템", true), //$NON-NLS-1$
        WAL("DB WAL (pg_wal)", false), //$NON-NLS-1$
        DATABASE("Engine DB 크기", false), //$NON-NLS-1$
        // Leveled against ENGINE_AUDIT_EVENT_TABLES_MAX_SIZE_MB; shown for reference when that is 0.
        EVENT_TABLES("이벤트 테이블 (한도)", true), //$NON-NLS-1$
        LOG_FILESYSTEM("로그 파일시스템", true), //$NON-NLS-1$
        FILE_LOG("엔진 로그 디렉터리 (한도)", true), //$NON-NLS-1$
        BACKUP_FILESYSTEM("백업 저장소 (설정)", true), //$NON-NLS-1$
        // The path typed on the protection tab. It is measured for the administrator and for the
        // backup and restore guards, but never raises events: it changes with whatever is typed.
        SELECTED_BACKUP_FILESYSTEM("백업 저장소 (입력한 저장 위치)", true); //$NON-NLS-1$

        private final String label;
        private final boolean leveled;

        Target(String label, boolean leveled) {
            this.label = label;
            this.leveled = leveled;
        }

        public String getLabel() {
            return label;
        }

        public boolean isLeveled() {
            return leveled;
        }

        public boolean isReported() {
            return leveled && this != SELECTED_BACKUP_FILESYSTEM;
        }
    }

    private final Target target;
    private final String path;
    private final long usedBytes;
    private final long capacityBytes;
    private final double usedPercent;
    private final Level level;
    private final String device;
    private final String detail;
    private final boolean expectedGap;

    private AuditStorageUsage(Target target, String path, long usedBytes, long capacityBytes,
            double usedPercent, Level level, String device, String detail) {
        this(target, path, usedBytes, capacityBytes, usedPercent, level, device, detail, false);
    }

    private AuditStorageUsage(Target target, String path, long usedBytes, long capacityBytes,
            double usedPercent, Level level, String device, String detail, boolean expectedGap) {
        this.target = target;
        this.path = path == null ? "" : path; //$NON-NLS-1$
        this.usedBytes = usedBytes;
        this.capacityBytes = capacityBytes;
        this.usedPercent = usedPercent;
        this.level = level;
        this.device = device == null ? "" : device; //$NON-NLS-1$
        this.detail = detail == null ? "" : detail; //$NON-NLS-1$
        this.expectedGap = expectedGap;
    }

    /**
     * A store with a capacity. Its usage is {@code usedBytes} of {@code capacityBytes}, where the
     * capacity of a file system is what is used plus what an unprivileged writer may still use,
     * the way df reports it.
     */
    public static AuditStorageUsage leveled(Target target, String path, long usedBytes, long capacityBytes,
            String device, AuditStorageThresholds thresholds, String detail) {
        return leveled(target, path, usedBytes, capacityBytes, usedPercent(usedBytes, capacityBytes), device,
                thresholds, detail);
    }

    /**
     * A store whose level is decided by a percentage other than its byte usage, such as the inode
     * usage of a file system.
     */
    public static AuditStorageUsage leveled(Target target, String path, long usedBytes, long capacityBytes,
            double usedPercent, String device, AuditStorageThresholds thresholds, String detail) {
        return new AuditStorageUsage(target, path, usedBytes, capacityBytes, usedPercent,
                thresholds.levelOf(usedPercent), device, detail);
    }

    /**
     * A size that is followed but has no capacity of its own.
     */
    public static AuditStorageUsage informational(Target target, String path, long usedBytes, String detail) {
        return new AuditStorageUsage(target, path, usedBytes, 0, -1, Level.NORMAL, "", detail); //$NON-NLS-1$
    }

    /**
     * A store that could not be measured, and why.
     */
    public static AuditStorageUsage unknown(Target target, String path, String reason) {
        return new AuditStorageUsage(target, path, 0, 0, -1, Level.UNKNOWN, "", reason); //$NON-NLS-1$
    }

    /**
     * A store that cannot be measured from here by design - the file system of a database on
     * another server - and so is not reported as a failure.
     */
    public static AuditStorageUsage unavailable(Target target, String path, String reason) {
        return new AuditStorageUsage(target, path, 0, 0, -1, Level.UNKNOWN, "", reason, true); //$NON-NLS-1$
    }

    static double usedPercent(long usedBytes, long capacityBytes) {
        if (capacityBytes <= 0) {
            return usedBytes > 0 ? 100 : 0;
        }
        return Math.min(100.0, Math.max(0.0, usedBytes * 100.0 / capacityBytes));
    }

    AuditStorageUsage withDetail(String extraDetail) {
        if (extraDetail == null || extraDetail.isEmpty()) {
            return this;
        }
        String combined = detail.isEmpty() ? extraDetail : detail + "; " + extraDetail; //$NON-NLS-1$
        return new AuditStorageUsage(target, path, usedBytes, capacityBytes, usedPercent, level, device, combined,
                expectedGap);
    }

    public Target getTarget() {
        return target;
    }

    public String getPath() {
        return path;
    }

    public long getUsedBytes() {
        return usedBytes;
    }

    public long getCapacityBytes() {
        return capacityBytes;
    }

    /**
     * @return the used percentage, or a negative number when the store has no capacity or could
     *         not be measured
     */
    public double getUsedPercent() {
        return usedPercent;
    }

    public long getRemainingPercent() {
        return usedPercent < 0 ? 0 : (long) Math.floor(100.0 - usedPercent);
    }

    public Level getLevel() {
        return level;
    }

    /**
     * @return an identifier of the file system, so two paths on the same file system are known to
     *         share their free space, or an empty string
     */
    public String getDevice() {
        return device;
    }

    public String getDetail() {
        return detail;
    }

    public boolean isExpectedGap() {
        return expectedGap;
    }

    public boolean isMeasured() {
        return level != Level.UNKNOWN;
    }
}
