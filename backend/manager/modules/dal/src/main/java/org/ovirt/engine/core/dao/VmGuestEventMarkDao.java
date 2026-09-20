package org.ovirt.engine.core.dao;

import java.util.List;

import org.ovirt.engine.core.common.businessentities.VmGuestEventMark;
import org.ovirt.engine.core.compat.Guid;

/**
 * Access to the marks that say where the guest event collector stopped reading each event log of
 * a virtual machine.
 */
public interface VmGuestEventMarkDao extends Dao {

    /** The marks held for one VM, one per log that has been read at least once. */
    List<VmGuestEventMark> getByVmId(Guid vmId);

    /**
     * Sets a mark. It is set rather than raised: a guest whose log was cleared numbers its records
     * from one again, and the mark has to be able to follow it down.
     */
    void save(VmGuestEventMark mark);
}
