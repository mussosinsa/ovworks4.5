package org.ovirt.engine.core.common.action;

import org.ovirt.engine.core.compat.Guid;

/** Parameters for executing an approved script or network operation through the QEMU guest agent. */
public class ExecuteVmGuestCommandParameters extends VmOperationParameterBase {
    private String path;
    private Boolean networkEnabled;
    private String ipAddress;
    private String subnetMask;
    private String gateway;
    private Boolean fileSharingBlocked;

    public ExecuteVmGuestCommandParameters() {
    }

    public ExecuteVmGuestCommandParameters(Guid vmId, String path) {
        super(vmId);
        this.path = path;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public Boolean getNetworkEnabled() {
        return networkEnabled;
    }

    public void setNetworkEnabled(Boolean networkEnabled) {
        this.networkEnabled = networkEnabled;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getSubnetMask() {
        return subnetMask;
    }

    public void setSubnetMask(String subnetMask) {
        this.subnetMask = subnetMask;
    }

    public String getGateway() {
        return gateway;
    }

    public void setGateway(String gateway) {
        this.gateway = gateway;
    }

    public Boolean getFileSharingBlocked() {
        return fileSharingBlocked;
    }

    public void setFileSharingBlocked(Boolean fileSharingBlocked) {
        this.fileSharingBlocked = fileSharingBlocked;
    }
}
