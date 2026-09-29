package org.ovirt.engine.core.common.businessentities;

import java.io.Serializable;
import java.util.Date;

/**
 * How much of the space allowed for audit records is in use.
 *
 * <p>The engine already watched this and raised an alert when it ran short, which is what an
 * administrator is told when it is already a problem. It was not something they could look at:
 * there was no screen that said how full the storage was, so the only way to find out was to wait
 * for the alert. This is what such a screen reads.</p>
 *
 * <p>A reading, not a setting: everything in it either was measured or is the configuration the
 * measurement was taken against. Nothing here is written back.</p>
 */
public class AuditLogCapacityStatus implements Serializable {

    private static final long serialVersionUID = 4508417321908812041L;

    /** Where the state came from, and what it means for the space left. */
    public enum State {
        /** Measured, and comfortably inside the limit. */
        NORMAL,
        /** Measured, and within the margin the engine warns at. */
        WARNING,
        /** Measured, and at or over the limit. */
        EXCEEDED,
        /** Monitoring is switched off by configuration, so nothing is being measured. */
        DISABLED,
        /** Monitoring is on, but the measurement could not be taken. */
        UNAVAILABLE
    }

    private State state;

    /** The directory the records are kept in. */
    private String directory;

    private long usedBytes;

    /** The limit, from {@code ENGINE_AUDIT_LOG_MAX_SIZE_MB}. Zero when monitoring is off. */
    private long maxBytes;

    /** How much of the limit is left, as a whole percentage. Zero once it is reached. */
    private long remainingPercent;

    /** The margin the engine raises its warning at, so the screen can say where the line is. */
    private int warningRemainingPercent;

    /** How often the engine measures, from {@code ENGINE_AUDIT_LOG_CAPACITY_CHECK_INTERVAL_SECONDS}. */
    private long checkIntervalSeconds;

    /** When the reading was taken, or null when none has been. */
    private Date measuredAt;

    /**
     * Whether the reading was taken to answer this request rather than by the monitor.
     *
     * <p>Worth saying on the screen: a reading of its own is current to the second, and the
     * monitor's is as old as its interval. Reading them as the same thing would have somebody
     * refreshing a screen that cannot change until the next pass.</p>
     */
    private boolean measuredOnDemand;

    /** Why there is no reading, when there is none. Empty otherwise. */
    private String unavailableReason;

    public AuditLogCapacityStatus() {
        state = State.UNAVAILABLE;
        directory = ""; //$NON-NLS-1$
        unavailableReason = ""; //$NON-NLS-1$
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    public String getDirectory() {
        return directory;
    }

    public void setDirectory(String directory) {
        this.directory = directory;
    }

    public long getUsedBytes() {
        return usedBytes;
    }

    public void setUsedBytes(long usedBytes) {
        this.usedBytes = usedBytes;
    }

    public long getMaxBytes() {
        return maxBytes;
    }

    public void setMaxBytes(long maxBytes) {
        this.maxBytes = maxBytes;
    }

    public long getRemainingPercent() {
        return remainingPercent;
    }

    public void setRemainingPercent(long remainingPercent) {
        this.remainingPercent = remainingPercent;
    }

    public int getWarningRemainingPercent() {
        return warningRemainingPercent;
    }

    public void setWarningRemainingPercent(int warningRemainingPercent) {
        this.warningRemainingPercent = warningRemainingPercent;
    }

    public long getCheckIntervalSeconds() {
        return checkIntervalSeconds;
    }

    public void setCheckIntervalSeconds(long checkIntervalSeconds) {
        this.checkIntervalSeconds = checkIntervalSeconds;
    }

    public Date getMeasuredAt() {
        return measuredAt;
    }

    public void setMeasuredAt(Date measuredAt) {
        this.measuredAt = measuredAt;
    }

    public boolean isMeasuredOnDemand() {
        return measuredOnDemand;
    }

    public void setMeasuredOnDemand(boolean measuredOnDemand) {
        this.measuredOnDemand = measuredOnDemand;
    }

    public String getUnavailableReason() {
        return unavailableReason;
    }

    public void setUnavailableReason(String unavailableReason) {
        this.unavailableReason = unavailableReason;
    }

    /** Whether there is a reading to show at all. */
    public boolean isMeasured() {
        return state == State.NORMAL || state == State.WARNING || state == State.EXCEEDED;
    }

    /**
     * How much of the limit is in use, as a whole percentage, for a bar on a screen.
     *
     * <p>Capped at a hundred: the space in use can pass the limit - that is what EXCEEDED means -
     * and a bar drawn longer than the space it is drawn in reads as a rendering fault rather than
     * as the fact it is reporting.</p>
     */
    public long getUsedPercent() {
        if (maxBytes <= 0) {
            return 0;
        }
        long percent = usedBytes * 100 / maxBytes;
        return percent > 100 ? 100 : percent;
    }
}
