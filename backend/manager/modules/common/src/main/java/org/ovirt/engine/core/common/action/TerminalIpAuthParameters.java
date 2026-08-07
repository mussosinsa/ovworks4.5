package org.ovirt.engine.core.common.action;

public class TerminalIpAuthParameters extends ActionParametersBase {
    private static final long serialVersionUID = 1L;

    private String ipAddress;

    public TerminalIpAuthParameters() {
    }

    public TerminalIpAuthParameters(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
}
