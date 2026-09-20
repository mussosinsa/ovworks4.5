package org.ovirt.engine.core.common.businessentities;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

import org.ovirt.engine.core.compat.Guid;

/**
 * How far the guest event collector has read one event log of one virtual machine.
 *
 * <p>Windows numbers the records of each log on its own, so the System log and the Security log of
 * the same machine are counted apart. Kept in the database rather than in the engine's memory,
 * because a restart would otherwise report again everything the lookback window still holds.
 */
public class VmGuestEventMark implements Serializable {

    private static final long serialVersionUID = 4139172993477256701L;

    private Guid vmId;
    private String logName;
    private long lastRecordId;
    private Date updateDate;

    public VmGuestEventMark() {
    }

    public VmGuestEventMark(Guid vmId, String logName, long lastRecordId) {
        this.vmId = vmId;
        this.logName = logName;
        this.lastRecordId = lastRecordId;
    }

    public Guid getVmId() {
        return vmId;
    }

    public void setVmId(Guid vmId) {
        this.vmId = vmId;
    }

    public String getLogName() {
        return logName;
    }

    public void setLogName(String logName) {
        this.logName = logName;
    }

    public long getLastRecordId() {
        return lastRecordId;
    }

    public void setLastRecordId(long lastRecordId) {
        this.lastRecordId = lastRecordId;
    }

    public Date getUpdateDate() {
        return updateDate;
    }

    public void setUpdateDate(Date updateDate) {
        this.updateDate = updateDate;
    }

    @Override
    public int hashCode() {
        return Objects.hash(vmId, logName, lastRecordId);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof VmGuestEventMark)) {
            return false;
        }
        VmGuestEventMark other = (VmGuestEventMark) obj;
        return Objects.equals(vmId, other.vmId)
                && Objects.equals(logName, other.logName)
                && lastRecordId == other.lastRecordId;
    }

    @Override
    public String toString() {
        return "VmGuestEventMark{vmId=" + vmId + ", logName=" + logName
                + ", lastRecordId=" + lastRecordId + "}";
    }
}
