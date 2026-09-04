package org.ovirt.engine.core.bll;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.EngineSSHClient;
import org.ovirt.engine.core.common.action.ExecuteVmGuestCommandParameters;
import org.ovirt.engine.core.common.businessentities.VDS;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.dao.VdsDao;
import org.ovirt.engine.core.utils.JsonHelper;

/** Executes an approved Windows batch file or network operation through the VM's QEMU guest agent. */
public class ExecuteVmGuestCommandCommand<T extends ExecuteVmGuestCommandParameters>
        extends VmOperationCommandBase<T> {
    private static final int POLL_ATTEMPTS = 60;
    private static final long POLL_INTERVAL_MILLIS = 1000;

    @Inject
    private VdsDao vdsDao;

    public ExecuteVmGuestCommandCommand(T parameters, CommandContext commandContext) {
        super(parameters, commandContext);
    }

    @Override
    protected boolean validate() {
        if (getVm() == null) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_VM_NOT_FOUND);
        }
        if (!getVm().isRunning() || getVm().getRunOnVds() == null) {
            return failVmStatusIllegal();
        }
        if (getParameters().getNetworkEnabled() != null && getParameters().getFileSharingBlocked() != null) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_INVALID_CUSTOM_PROPERTIES_INVALID_SYNTAX);
        }
        if (getParameters().getNetworkEnabled() != null) {
            if (getParameters().getNetworkEnabled()
                    && (!isIpv4(getParameters().getIpAddress())
                            || prefixLength(getParameters().getSubnetMask()) < 0
                            || !isIpv4(getParameters().getGateway()))) {
                return failValidation(EngineMessage.ACTION_TYPE_FAILED_INVALID_CUSTOM_PROPERTIES_INVALID_SYNTAX);
            }
            return true;
        }
        if (getParameters().getFileSharingBlocked() != null) {
            return true;
        }
        String path = getParameters().getPath();
        if (StringUtils.isBlank(path) || !path.matches("(?i)^[a-z]:\\\\[^\\r\\n'\"]+\\.bat$")) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_INVALID_CUSTOM_PROPERTIES_INVALID_SYNTAX);
        }
        return true;
    }

    @Override
    protected void perform() {
        VDS host = vdsDao.get(getVm().getRunOnVds());
        if (host == null) {
            setSucceeded(false);
            return;
        }
        try (EngineSSHClient ssh = new EngineSSHClient()) {
            ssh.setVds(host);
            ssh.useDefaultKeyPair();
            ssh.connect();
            ssh.authenticate();

            String executable = getParameters().getPath();
            List<String> arguments = Collections.emptyList();
            if (getParameters().getNetworkEnabled() != null) {
                executable = "powershell.exe"; //$NON-NLS-1$
                arguments = java.util.Arrays.asList("-Command", networkCommand( //$NON-NLS-1$
                        getParameters().getNetworkEnabled(),
                        getParameters().getIpAddress(),
                        getParameters().getSubnetMask(),
                        getParameters().getGateway()));
            } else if (getParameters().getFileSharingBlocked() != null) {
                executable = "powershell.exe"; //$NON-NLS-1$
                arguments = java.util.Arrays.asList(
                        "-Command", fileSharingCommand(getParameters().getFileSharingBlocked())); //$NON-NLS-1$
            }
            String request = guestExecRequest(executable, arguments);
            Map<String, Object> start = execute(ssh, request);
            Object pid = ((Map<?, ?>) start.get("return")).get("pid");
            if (pid == null) {
                throw new IllegalStateException("QEMU guest agent did not return a process id");
            }

            for (int attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
                Map<String, Object> status = execute(ssh,
                        "{\"execute\":\"guest-exec-status\",\"arguments\":{\"pid\":" + pid + "}}");
                Map<?, ?> result = (Map<?, ?>) status.get("return");
                if (Boolean.TRUE.equals(result.get("exited"))) {
                    String output = decode(result.get("out-data"));
                    String error = decode(result.get("err-data"));
                    String value = "exit-code=" + result.get("exitcode") + "\nstdout:\n" + output
                            + (error.isEmpty() ? "" : "\nstderr:\n" + error);
                    getReturnValue().setActionReturnValue(value);
                    setSucceeded(((Number) result.get("exitcode")).intValue() == 0);
                    return;
                }
                Thread.sleep(POLL_INTERVAL_MILLIS);
            }
            throw new IllegalStateException("Timed out waiting for guest command result");
        } catch (Exception e) {
            log.error("Failed to execute guest command on VM '{}' through host '{}': {}",
                    getVm().getName(), getVm().getRunOnVdsName(), e.getMessage());
            getReturnValue().getExecuteFailedMessages().add(e.getMessage());
            setSucceeded(false);
        }
    }

    private Map<String, Object> execute(EngineSSHClient ssh, String request) throws Exception {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream();
                ByteArrayOutputStream err = new ByteArrayOutputStream()) {
            String command = "virsh qemu-agent-command " + shellQuote(getVm().getName())
                    + " --command " + shellQuote(request);
            ssh.executeCommand(command, null, out, err);
            String response = out.toString(StandardCharsets.UTF_8.name()).trim();
            if (response.isEmpty()) {
                throw new IllegalStateException(err.toString(StandardCharsets.UTF_8.name()).trim());
            }
            return JsonHelper.jsonToMap(response);
        }
    }

    static String networkCommand(boolean enabled, String ipAddress, String subnetMask, String gateway) {
        String adapter = "\uc774\ub354\ub137"; //$NON-NLS-1$
        if (!enabled) {
            return "Disable-NetAdapter -Name \"" + adapter + "\" -Confirm:$false"; //$NON-NLS-1$ //$NON-NLS-2$
        }
        return "Enable-NetAdapter -Name \"" + adapter + "\" -Confirm:$false; " //$NON-NLS-1$ //$NON-NLS-2$
                + "Remove-NetIPAddress -InterfaceAlias \"" + adapter //$NON-NLS-1$
                + "\" -Confirm:$false -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + "New-NetIPAddress -InterfaceAlias \"" + adapter + "\" -IPAddress " //$NON-NLS-1$ //$NON-NLS-2$
                + ipAddress + " -PrefixLength " + prefixLength(subnetMask) //$NON-NLS-1$
                + " -DefaultGateway " + gateway; //$NON-NLS-1$
    }

    static String fileSharingCommand(boolean blocked) {
        if (blocked) {
            return "New-NetFirewallRule -DisplayName \"Block_SMB\" -Direction Inbound -Protocol TCP " //$NON-NLS-1$
                    + "-LocalPort 139,445 -Action Block -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                    + "New-NetFirewallRule -DisplayName \"Block_SMB_Outbound\" -Direction Outbound " //$NON-NLS-1$
                    + "-Protocol TCP -RemotePort 139,445 -Action Block -ErrorAction SilentlyContinue"; //$NON-NLS-1$
        }
        return "Remove-NetFirewallRule -DisplayName \"Block_SMB\" -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + "Remove-NetFirewallRule -DisplayName \"Block_SMB_Outbound\" " //$NON-NLS-1$
                + "-ErrorAction SilentlyContinue"; //$NON-NLS-1$
    }

    private static String guestExecRequest(String path, List<String> arguments) {
        StringBuilder args = new StringBuilder();
        for (String argument : arguments) {
            if (args.length() > 0) {
                args.append(',');
            }
            args.append('"').append(jsonEscape(argument)).append('"');
        }
        return "{\"execute\":\"guest-exec\",\"arguments\":{\"path\":\"" + jsonEscape(path)
                + "\",\"args\":[" + args + "],\"capture-output\":true}}";
    }

    private static boolean isIpv4(String value) {
        if (value == null || !value.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return false;
        }
        for (String octet : value.split("\\.")) {
            if (Integer.parseInt(octet) > 255) {
                return false;
            }
        }
        return true;
    }

    private static int prefixLength(String mask) {
        if (!isIpv4(mask)) {
            return -1;
        }
        long value = 0;
        for (String octet : mask.split("\\.")) {
            value = (value << 8) | Integer.parseInt(octet);
        }
        long inverted = (~value) & 0xffffffffL;
        if ((inverted & (inverted + 1)) != 0) {
            return -1;
        }
        return Long.bitCount(value);
    }

    static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\\"'\\\"'") + "'";
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String decode(Object value) {
        return value == null ? "" : new String(Base64.getDecoder().decode(value.toString()), StandardCharsets.UTF_8);
    }
}
