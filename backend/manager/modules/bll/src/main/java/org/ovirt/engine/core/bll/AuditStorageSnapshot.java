package org.ovirt.engine.core.bll;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import org.ovirt.engine.core.bll.AuditStorageThresholds.Level;
import org.ovirt.engine.core.bll.AuditStorageUsage.Target;

/**
 * Everything one pass of the audit record storage monitor measured, and the decisions the backup
 * and restore commands take from it.
 */
public final class AuditStorageSnapshot {

    static final String ROW_META = "META"; //$NON-NLS-1$
    static final String ROW_USAGE = "USAGE"; //$NON-NLS-1$
    static final String ROW_MAINTENANCE = "MAINTENANCE"; //$NON-NLS-1$

    private final Date measuredAt;
    private final long checkIntervalSeconds;
    private final AuditStorageThresholds thresholds;
    private final List<AuditStorageUsage> usages;
    private final List<String> maintenanceWarnings;

    public AuditStorageSnapshot(Date measuredAt, long checkIntervalSeconds, AuditStorageThresholds thresholds,
            List<AuditStorageUsage> usages, List<String> maintenanceWarnings) {
        this.measuredAt = new Date(measuredAt.getTime());
        this.checkIntervalSeconds = checkIntervalSeconds;
        this.thresholds = thresholds;
        this.usages = Collections.unmodifiableList(new ArrayList<>(usages));
        this.maintenanceWarnings = Collections.unmodifiableList(new ArrayList<>(maintenanceWarnings));
    }

    public Date getMeasuredAt() {
        return new Date(measuredAt.getTime());
    }

    public AuditStorageThresholds getThresholds() {
        return thresholds;
    }

    public List<AuditStorageUsage> getUsages() {
        return usages;
    }

    public List<String> getMaintenanceWarnings() {
        return maintenanceWarnings;
    }

    public AuditStorageUsage get(Target target) {
        for (AuditStorageUsage usage : usages) {
            if (usage.getTarget() == target) {
                return usage;
            }
        }
        return null;
    }

    /**
     * @return the most serious level of the stores that were measured
     */
    public Level getOverallLevel() {
        Level worst = Level.NORMAL;
        for (AuditStorageUsage usage : usages) {
            if (usage.getTarget().isLeveled() && usage.getLevel().compareTo(worst) > 0) {
                worst = usage.getLevel();
            }
        }
        return worst;
    }

    /**
     * A restore first dumps the current events next to the backups, then writes the restored rows
     * into the database. Either can fill a store that is already at the high level, so the restore
     * waits until the storage has been expanded.
     *
     * @return why the restore must not run, or {@code null}
     */
    public String restoreBlockReason() {
        for (Target target : new Target[] { Target.DB_FILESYSTEM, Target.SELECTED_BACKUP_FILESYSTEM }) {
            AuditStorageUsage usage = get(target);
            if (usage != null && usage.getLevel().compareTo(Level.HIGH) >= 0) {
                return String.format(
                        "%s 사용률이 %s%%(%s 단계)로 복구 허용 한도(%d%% 미만)를 넘었습니다. "  //$NON-NLS-1$
                                + "복구는 현재 이벤트를 먼저 덤프하고 DB에 다시 기록하므로 저장공간을 증설한 뒤 실행하십시오.", //$NON-NLS-1$
                        usage.getTarget().getLabel(),
                        formatPercent(usage.getUsedPercent()),
                        usage.getLevel().getLabel(),
                        thresholds.getHigh());
            }
        }
        return null;
    }

    /**
     * A backup is what an administrator is asked to take when the storage fills up, so it is only
     * refused when it would make things worse: when its destination is itself at the critical
     * level, or shares its file system with a database that is already at the high level.
     *
     * @return why the backup must not run, or {@code null}
     */
    public String backupBlockReason() {
        AuditStorageUsage destination = get(Target.SELECTED_BACKUP_FILESYSTEM);
        if (destination == null || !destination.isMeasured()) {
            return null;
        }
        if (destination.getLevel().compareTo(Level.CRITICAL) >= 0) {
            return String.format(
                    "백업 저장 위치의 파일시스템 사용률이 %s%%(%s 단계)입니다. 다른 볼륨을 저장 위치로 지정하십시오.", //$NON-NLS-1$
                    formatPercent(destination.getUsedPercent()),
                    destination.getLevel().getLabel());
        }
        AuditStorageUsage database = get(Target.DB_FILESYSTEM);
        if (database != null && database.isMeasured()
                && !destination.getDevice().isEmpty()
                && destination.getDevice().equals(database.getDevice())
                && database.getLevel().compareTo(Level.HIGH) >= 0) {
            return String.format(
                    "백업 저장 위치가 DB 데이터와 같은 파일시스템에 있고 사용률이 %s%%(%s 단계)입니다. " //$NON-NLS-1$
                            + "백업 파일이 DB 공간을 소진할 수 있으므로 별도 볼륨을 저장 위치로 지정하십시오.", //$NON-NLS-1$
                    formatPercent(database.getUsedPercent()),
                    database.getLevel().getLabel());
        }
        return null;
    }

    /**
     * @return a caution to show with a backup that was allowed, or {@code null}
     */
    public String backupCaution() {
        AuditStorageUsage destination = get(Target.SELECTED_BACKUP_FILESYSTEM);
        if (destination == null) {
            return null;
        }
        if (!destination.isMeasured()) {
            return "백업 저장 위치의 여유 공간을 확인하지 못했습니다: " + destination.getDetail(); //$NON-NLS-1$
        }
        AuditStorageUsage database = get(Target.DB_FILESYSTEM);
        if (database != null && !destination.getDevice().isEmpty()
                && destination.getDevice().equals(database.getDevice())) {
            return "백업 저장 위치가 DB 데이터와 같은 파일시스템에 있습니다. 백업은 별도 볼륨에 보관하는 것을 권장합니다."; //$NON-NLS-1$
        }
        if (destination.getLevel().compareTo(Level.HIGH) >= 0) {
            return String.format("백업 저장 위치의 사용률이 %s%%(%s 단계)입니다.", //$NON-NLS-1$
                    formatPercent(destination.getUsedPercent()), destination.getLevel().getLabel());
        }
        return null;
    }

    /**
     * The snapshot as tab separated rows for the web administration tab, which cannot receive
     * engine classes: a META row, one USAGE row per store and one MAINTENANCE row per warning.
     */
    public List<String> toRows() {
        List<String> rows = new ArrayList<>();
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT); //$NON-NLS-1$
        Level overall = getOverallLevel();
        rows.add(join(ROW_META,
                format.format(measuredAt),
                Long.toString(checkIntervalSeconds),
                thresholds.toString(),
                overall.name(),
                overall.getLabel()));
        for (AuditStorageUsage usage : usages) {
            rows.add(join(ROW_USAGE,
                    usage.getTarget().name(),
                    usage.getTarget().getLabel(),
                    usage.getLevel().name(),
                    usage.getLevel().getLabel(),
                    usage.getUsedPercent() < 0 ? "" : formatPercent(usage.getUsedPercent()), //$NON-NLS-1$
                    Long.toString(usage.getUsedBytes()),
                    Long.toString(usage.getCapacityBytes()),
                    usage.getPath(),
                    usage.getDetail()));
        }
        for (String warning : maintenanceWarnings) {
            rows.add(join(ROW_MAINTENANCE, warning));
        }
        return rows;
    }

    static String formatPercent(double percent) {
        return String.format(Locale.ROOT, "%.1f", percent); //$NON-NLS-1$
    }

    private static String join(String... fields) {
        StringBuilder builder = new StringBuilder();
        for (String field : fields) {
            if (builder.length() > 0) {
                builder.append('\t');
            }
            builder.append(field == null ? "" : field.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')); //$NON-NLS-1$
        }
        return builder.toString();
    }
}
