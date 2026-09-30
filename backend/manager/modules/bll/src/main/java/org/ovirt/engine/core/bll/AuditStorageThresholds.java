package org.ovirt.engine.core.bll;

import org.ovirt.engine.core.common.AuditLogType;

/**
 * The usage percentages at which a store of audit records is reported, and what each level is
 * called. A store that is full is always {@link Level#FULL}, whatever the thresholds are.
 */
public final class AuditStorageThresholds {

    public static final String DEFAULT_VALUE = "70,80,90,95"; //$NON-NLS-1$
    public static final AuditStorageThresholds DEFAULT = new AuditStorageThresholds(70, 80, 90, 95);

    /**
     * Ordered from the least to the most serious, so {@link Enum#compareTo} tells which of two
     * levels is worse.
     */
    public enum Level {
        UNKNOWN("측정 불가", null), //$NON-NLS-1$
        NORMAL("정상", AuditLogType.AUDIT_LOG_CAPACITY_RECOVERED), //$NON-NLS-1$
        NOTICE("주의", AuditLogType.AUDIT_STORAGE_USAGE_NOTICE), //$NON-NLS-1$
        WARNING("경계", AuditLogType.AUDIT_STORAGE_USAGE_WARNING), //$NON-NLS-1$
        HIGH("심각", AuditLogType.AUDIT_STORAGE_USAGE_HIGH), //$NON-NLS-1$
        // The two most serious levels keep the events that were raised before the storage had
        // levels, so that subscriptions to them carry on notifying.
        CRITICAL("위기", AuditLogType.AUDIT_LOG_CAPACITY_WARNING), //$NON-NLS-1$
        FULL("포화", AuditLogType.AUDIT_LOG_CAPACITY_EXCEEDED); //$NON-NLS-1$

        private final String label;
        private final AuditLogType eventType;

        Level(String label, AuditLogType eventType) {
            this.label = label;
            this.eventType = eventType;
        }

        public String getLabel() {
            return label;
        }

        public AuditLogType getEventType() {
            return eventType;
        }

        /**
         * Whether a store at this level is still reported on every check, rather than only when it
         * reaches the level. The event flood regulator keeps the repeats to one an hour.
         */
        public boolean isRepeated() {
            return compareTo(HIGH) >= 0;
        }

        public boolean isAbnormal() {
            return compareTo(NOTICE) >= 0;
        }
    }

    private final int notice;
    private final int warning;
    private final int high;
    private final int critical;

    AuditStorageThresholds(int notice, int warning, int high, int critical) {
        this.notice = notice;
        this.warning = warning;
        this.high = high;
        this.critical = critical;
    }

    public int getNotice() {
        return notice;
    }

    public int getWarning() {
        return warning;
    }

    public int getHigh() {
        return high;
    }

    public int getCritical() {
        return critical;
    }

    public Level levelOf(double usedPercent) {
        if (usedPercent >= 100) {
            return Level.FULL;
        }
        if (usedPercent >= critical) {
            return Level.CRITICAL;
        }
        if (usedPercent >= high) {
            return Level.HIGH;
        }
        if (usedPercent >= warning) {
            return Level.WARNING;
        }
        if (usedPercent >= notice) {
            return Level.NOTICE;
        }
        return Level.NORMAL;
    }

    @Override
    public String toString() {
        return notice + "," + warning + "," + high + "," + critical; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    }

    /**
     * Reads the configured thresholds, falling back to the defaults when the value cannot be used,
     * so a mistyped value never leaves the storage unwatched.
     */
    public static AuditStorageThresholds parseOrDefault(String value) {
        return validate(value) == null ? parse(value) : DEFAULT;
    }

    /**
     * @return why the value cannot be used as thresholds, or {@code null} when it can
     */
    public static String validate(String value) {
        if (value == null) {
            return "임계치 값이 비어 있습니다."; //$NON-NLS-1$
        }
        String[] parts = value.split(",", -1); //$NON-NLS-1$
        if (parts.length != 4) {
            return "임계치는 쉼표로 구분한 4개의 백분율(주의,경계,심각,위기)이어야 합니다. 예: 70,80,90,95"; //$NON-NLS-1$
        }
        int previous = 0;
        for (String part : parts) {
            int percent;
            try {
                percent = Integer.parseInt(part.trim());
            } catch (NumberFormatException exception) {
                return "임계치에 숫자가 아닌 값이 있습니다: " + part.trim(); //$NON-NLS-1$
            }
            if (percent < 1 || percent > 99) {
                return "임계치는 1에서 99 사이여야 합니다: " + percent; //$NON-NLS-1$
            }
            if (percent <= previous) {
                return "임계치는 주의 < 경계 < 심각 < 위기 순으로 커져야 합니다."; //$NON-NLS-1$
            }
            previous = percent;
        }
        return null;
    }

    private static AuditStorageThresholds parse(String value) {
        String[] parts = value.split(","); //$NON-NLS-1$
        return new AuditStorageThresholds(
                Integer.parseInt(parts[0].trim()),
                Integer.parseInt(parts[1].trim()),
                Integer.parseInt(parts[2].trim()),
                Integer.parseInt(parts[3].trim()));
    }
}
