package org.ovirt.engine.core.common.action;

import org.ovirt.engine.core.compat.Guid;

/** Parameters for executing an approved script or network operation through the QEMU guest agent. */
public class ExecuteVmGuestCommandParameters extends VmOperationParameterBase {
    /** Separates the time, log, level and message of one guest event line. */
    public static final String GUEST_EVENT_SEPARATOR = "\t"; //$NON-NLS-1$

    private String path;
    private Boolean networkEnabled;
    private String macAddress;
    private String ipAddress;
    private String subnetMask;
    private String gateway;
    private Boolean fileSharingBlocked;
    private Boolean cmdBlocked;
    private Boolean guestEventsRequested;
    private Boolean managementCommandsBlocked;
    private Boolean criticalEventsRequested;

    private Integer lookbackHours;

    private Boolean dhcp;

    private String dnsServer;

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

    public Boolean getManagementCommandsBlocked() {
        return managementCommandsBlocked;
    }

    public void setManagementCommandsBlocked(Boolean managementCommandsBlocked) {
        this.managementCommandsBlocked = managementCommandsBlocked;
    }

    public Boolean getGuestEventsRequested() {
        return guestEventsRequested;
    }

    public void setGuestEventsRequested(Boolean guestEventsRequested) {
        this.guestEventsRequested = guestEventsRequested;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
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

    public Boolean getCmdBlocked() {
        return cmdBlocked;
    }

    public void setCmdBlocked(Boolean cmdBlocked) {
        this.cmdBlocked = cmdBlocked;
    }

    /** Whether an enabled adapter asks for a lease instead of taking the address below. */
    public Boolean getDhcp() {
        return dhcp;
    }

    /** Ask what has gone seriously wrong inside the guest, rather than for everything it logged. */
    public Boolean getCriticalEventsRequested() {
        return criticalEventsRequested;
    }

    public void setCriticalEventsRequested(Boolean criticalEventsRequested) {
        this.criticalEventsRequested = criticalEventsRequested;
    }

    /** How far back to look. Absent means the default the command decides on. */
    public Integer getLookbackHours() {
        return lookbackHours;
    }

    public void setLookbackHours(Integer lookbackHours) {
        this.lookbackHours = lookbackHours;
    }

    public void setDhcp(Boolean dhcp) {
        this.dhcp = dhcp;
    }

    public String getDnsServer() {
        return dnsServer;
    }

    public void setDnsServer(String dnsServer) {
        this.dnsServer = dnsServer;
    }
}
