package org.ovirt.engine.core.bll;

import java.io.ByteArrayInputStream;
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
    private static final int MAX_CONSECUTIVE_AGENT_FAILURES = 3;
    private static final int AGENT_TIMEOUT_SECONDS = 60;
    /**
     * Denied to ordinary users; each is a way to change the network or a share.
     *
     * <p>By file name, with no folder in front of it. A Software Restriction path rule that names
     * only the file matches it wherever it is, so a copy dropped in a writable folder is refused
     * along with the original.</p>
     */
    private static final String[] BLOCKED_TOOLS = {
            "netsh.exe", "netcfg.exe", "ipconfig.exe", "route.exe", "arp.exe", "netstat.exe",
            "net.exe", "net1.exe",
            // The hosts an ordinary user would reach for once the tools above are gone.
            "powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe", "wmic.exe",
            "cscript.exe", "wscript.exe", "mshta.exe",
            "reg.exe", "regedit.exe", "control.exe", "rundll32.exe", "mmc.exe"
    };

    /**
     * The windows that offer the same changes as the tools above, and the applets behind them.
     *
     * <p>Software Restriction Policies judge these where an executable rule could not. A
     * {@code .cpl} is a library and a {@code .msc} is a snap-in definition, so neither is a program
     * and neither starts one: {@code control.exe} and {@code mmc.exe} load them. Both extensions
     * are on the list of file types Windows checks these rules against, which is what makes naming
     * them here enough - and what an executable whitelist could never do without taking away
     * {@code control.exe} and {@code mmc.exe} from everything else too.</p>
     */
    private static final String[] BLOCKED_SETTINGS_PAGES = {
            "firewall.cpl",   // Windows Defender Firewall
            "ncpa.cpl",       // Network Connections: an adapter is disabled or readdressed here
            "inetcpl.cpl",    // Internet Options, which is where the proxy is set
            "wscui.cpl",      // Security and Maintenance
            "sysdm.cpl",      // System Properties: remote desktop, the computer name
            "appwiz.cpl",     // Programs and Features, which turns Windows features on and off
            "hdwwiz.cpl",     // Device Manager: the network adapter can be removed here
            "wf.msc",         // Windows Defender Firewall with Advanced Security
            "ncpa.msc",       // Network Connections, again
            "services.msc"    // where the server service could be started again
    };

    /** How many guest events one refresh brings back. */
    private static final int GUEST_EVENT_LIMIT = 100;
    /** How far back a refresh looks, in hours. */
    private static final int GUEST_EVENT_HOURS = 24;
    /** How the output of a guest command reaches the dialog. */
    private enum ResultFormat {
        /** One line: the command reported its own verdict. */
        SUMMARY,
        /** The output itself, for a command whose output is the answer. */
        RAW,
        /** Exit code, output and errors, for a command supplied by the caller. */
        DETAILED
    }

    /** Kept well below the guest agent poll budget, since a command waits twice at most. */
    private static final int GUEST_WAIT_SECONDS = 15;

    /**
     * PowerShell writes its output in the ANSI code page of the guest unless the output encoding is
     * set explicitly, so anything but plain ASCII reaches the engine as mojibake. The encoding is
     * built without a byte order mark, which would otherwise be prepended to every result.
     */
    private static final String UTF8_OUTPUT =
            "$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; "; //$NON-NLS-1$

    /**
     * Runs a QEMU guest agent command on the host that runs the VM.
     *
     * <p>VDSM configures libvirt with {@code auth_unix_rw="sasl"}, so calling {@code virsh} as root
     * over SSH fails to authenticate and exits with a failure code. The script reuses the VDSM
     * libvirt connection helper, which already holds those credentials, and falls back to the SASL
     * credentials VDSM stores on disk when the VDSM python package cannot be imported.
     *
     * <p>The domain is looked up by UUID and the request is read from the standard input, so
     * neither the VM name nor the JSON request has to survive shell quoting.
     */
    static final String GUEST_AGENT_SCRIPT = String.join("\n",
            "import sys",
            "import libvirt",
            "import libvirt_qemu",
            "def credentials(creds, unused):",
            "    with open(\"/etc/pki/vdsm/keys/libvirt_password\") as stream:",
            "        password = stream.read().strip()",
            "    for cred in creds:",
            "        if cred[0] == libvirt.VIR_CRED_AUTHNAME:",
            "            cred[4] = \"vdsm@ovirt\"",
            "        elif cred[0] == libvirt.VIR_CRED_PASSPHRASE:",
            "            cred[4] = password",
            "    return 0",
            "def connect():",
            "    try:",
            "        from vdsm.common import libvirtconnection",
            "        return libvirtconnection.get(killOnFailure=False)",
            "    except Exception:",
            "        auth = [[libvirt.VIR_CRED_AUTHNAME, libvirt.VIR_CRED_PASSPHRASE], credentials, None]",
            "        return libvirt.openAuth(\"qemu:///system\", auth, 0)",
            "domain = connect().lookupByUUIDString(sys.argv[1])",
            "sys.stdout.write(libvirt_qemu.qemuAgentCommand(",
            "    domain, sys.stdin.read(), " + AGENT_TIMEOUT_SECONDS + ", 0))");

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
        int operationCount = (getParameters().getNetworkEnabled() == null ? 0 : 1)
                + (getParameters().getFileSharingBlocked() == null ? 0 : 1)
                + (getParameters().getCmdBlocked() == null ? 0 : 1)
                + (getParameters().getGuestEventsRequested() == null ? 0 : 1)
                + (getParameters().getManagementCommandsBlocked() == null ? 0 : 1);
        if (operationCount > 1) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_INVALID_CUSTOM_PROPERTIES_INVALID_SYNTAX);
        }
        if (getParameters().getGuestEventsRequested() != null
                || getParameters().getManagementCommandsBlocked() != null) {
            return true;
        }
        if (getParameters().getNetworkEnabled() != null) {
            if (!isMacAddress(getParameters().getMacAddress())) {
                return failValidation(EngineMessage.ACTION_TYPE_FAILED_INVALID_CUSTOM_PROPERTIES_INVALID_SYNTAX);
            }
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
        if (getParameters().getCmdBlocked() != null) {
            // Nothing to check: the request names no path of its own, and the program it decides
            // is named in the policy rather than by whoever asked for it.
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
            // Only the commands this class builds are known to report a single line.
            ResultFormat format = ResultFormat.SUMMARY;
            if (Boolean.TRUE.equals(getParameters().getGuestEventsRequested())) {
                executable = "powershell.exe"; //$NON-NLS-1$
                arguments = powerShellOutputArguments(guestEventsCommand());
                format = ResultFormat.RAW;
            } else if (getParameters().getNetworkEnabled() != null) {
                executable = "powershell.exe"; //$NON-NLS-1$
                boolean enabled = getParameters().getNetworkEnabled();
                boolean dhcp = Boolean.TRUE.equals(getParameters().getDhcp());
                arguments = powerShellArguments(
                        networkCommand(
                                enabled,
                                dhcp,
                                getParameters().getMacAddress(),
                                getParameters().getIpAddress(),
                                getParameters().getSubnetMask(),
                                getParameters().getGateway(),
                                getParameters().getDnsServer()),
                        !enabled ? "$name is disabled" //$NON-NLS-1$
                                : dhcp ? "$name is up on a lease" //$NON-NLS-1$
                                        : "$name is up with " + getParameters().getIpAddress()); //$NON-NLS-1$
            } else if (getParameters().getFileSharingBlocked() != null) {
                executable = "powershell.exe"; //$NON-NLS-1$
                arguments = powerShellArguments(
                        fileSharingCommand(getParameters().getFileSharingBlocked()),
                        getParameters().getFileSharingBlocked()
                                ? "file sharing is blocked" : "file sharing is allowed"); //$NON-NLS-1$ //$NON-NLS-2$
            } else if (getParameters().getManagementCommandsBlocked() != null) {
                executable = "powershell.exe"; //$NON-NLS-1$
                boolean blocked = getParameters().getManagementCommandsBlocked();
                arguments = powerShellArguments(
                        managementCommandsCommand(blocked),
                        blocked
                                ? "network and file sharing commands are blocked" //$NON-NLS-1$
                                : "network and file sharing commands are allowed again"); //$NON-NLS-1$
            } else if (getParameters().getCmdBlocked() != null) {
                executable = "powershell.exe"; //$NON-NLS-1$
                arguments = powerShellArguments(
                        cmdCommand(getParameters().getCmdBlocked()),
                        getParameters().getCmdBlocked()
                                ? "cmd.exe is refused to ordinary users" //$NON-NLS-1$
                                : "cmd.exe can be run again"); //$NON-NLS-1$
            } else {
                format = ResultFormat.DETAILED;
            }
            String request = guestExecRequest(executable, arguments);
            Map<String, Object> start = execute(ssh, request);
            Object pid = ((Map<?, ?>) start.get("return")).get("pid");
            if (pid == null) {
                throw new IllegalStateException("QEMU guest agent did not return a process id");
            }

            int consecutiveFailures = 0;
            for (int attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
                try {
                    Map<String, Object> status = execute(ssh,
                            "{\"execute\":\"guest-exec-status\",\"arguments\":{\"pid\":" + pid + "}}");
                    Map<?, ?> result = (Map<?, ?>) status.get("return");
                    if (Boolean.TRUE.equals(result.get("exited"))) {
                        int exitCode = ((Number) result.get("exitcode")).intValue();
                        String output = decode(result.get("out-data")).trim();
                        String error = decode(result.get("err-data")).trim();
                        String value;
                        if (format == ResultFormat.SUMMARY) {
                            value = summarize(exitCode, output, error);
                        } else if (format == ResultFormat.RAW) {
                            value = exitCode == 0 ? output : summarize(exitCode, output, error);
                        } else {
                            value = report(exitCode, output, error);
                        }
                        getReturnValue().setActionReturnValue(value);
                        setSucceeded(exitCode == 0);
                        return;
                    }
                    consecutiveFailures = 0;
                } catch (Exception e) {
                    // VDSM polls the same guest agent, so a status request can be rejected while
                    // VDSM holds it. Retry a few times before giving up on the command.
                    if (++consecutiveFailures > MAX_CONSECUTIVE_AGENT_FAILURES) {
                        throw e;
                    }
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
        try (ByteArrayInputStream in = new ByteArrayInputStream(request.getBytes(StandardCharsets.UTF_8));
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ByteArrayOutputStream err = new ByteArrayOutputStream()) {
            String command = guestAgentCommand(getVmId().toString());
            try {
                ssh.executeCommand(command, in, out, err);
            } catch (Exception e) {
                throw new IllegalStateException(describeFailure(e.getMessage(), err), e);
            }
            String response = out.toString(StandardCharsets.UTF_8.name()).trim();
            if (response.isEmpty()) {
                throw new IllegalStateException(describeFailure("", err));
            }
            return JsonHelper.jsonToMap(response);
        }
    }

    /**
     * Wraps a command so that it writes exactly one line: the success message, or the reason it
     * failed. Everything the cmdlets print on their own is dropped, and a failure leaves a non zero
     * exit code behind so the command is reported as failed.
     */
    /**
     * Lists the recent entries of the guest event logs, one event per line, as time, log, level and
     * message separated by tabs. Newlines are stripped from the message so that one event stays on
     * one line, and the message is cut short because the table only has room for a summary.
     */
    static String guestEventsCommand() {
        return "Get-WinEvent -ErrorAction SilentlyContinue -MaxEvents " + GUEST_EVENT_LIMIT //$NON-NLS-1$
                + " -FilterHashtable @{ LogName = @(\"System\", \"Application\", \"Security\"); " //$NON-NLS-1$
                + "StartTime = (Get-Date).AddHours(-" + GUEST_EVENT_HOURS + ") } | ForEach-Object { " //$NON-NLS-1$ //$NON-NLS-2$
                + "$message = \"\"; " //$NON-NLS-1$
                + "if ($_.Message) { $message = ($_.Message -replace \"[`r`n`t]+\", \" \").Trim() }; " //$NON-NLS-1$
                + "if ($message.Length -gt 200) { $message = $message.Substring(0, 200) }; " //$NON-NLS-1$
                + "\"{0}`t{1}`t{2}`t{3}\" -f $_.TimeCreated.ToString(\"yyyy-MM-dd HH:mm:ss\"), " //$NON-NLS-1$
                + "$_.LogName, $_.LevelDisplayName, $message }"; //$NON-NLS-1$
    }

    /**
     * Runs a command whose output is the answer, so nothing is suppressed. A failure still reports
     * one line, on the error stream, and leaves a non zero exit code behind.
     */
    static List<String> powerShellOutputArguments(String command) {
        return java.util.Arrays.asList("-Command", UTF8_OUTPUT //$NON-NLS-1$
                + "$ErrorActionPreference = \"Stop\"; " //$NON-NLS-1$
                + "try { " + command + " } " //$NON-NLS-1$ //$NON-NLS-2$
                + "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"); //$NON-NLS-1$
    }

    /** The managed commands print one line, so the dialog shows that line and nothing else. */
    static String summarize(int exitCode, String output, String error) {
        String line = lastLine(output);
        if (line.isEmpty()) {
            line = lastLine(error);
        }
        if (line.isEmpty()) {
            line = exitCode == 0 ? "OK" : "FAILED: exit code " + exitCode;
        }
        return line;
    }

    static String report(int exitCode, String output, String error) {
        return "exit-code=" + exitCode + "\nstdout:\n" + output
                + (error.isEmpty() ? "" : "\nstderr:\n" + error);
    }

    static List<String> powerShellArguments(String command, String successMessage) {
        return java.util.Arrays.asList("-Command", UTF8_OUTPUT //$NON-NLS-1$
                + "$ErrorActionPreference = \"Stop\"; " //$NON-NLS-1$
                // Dot sourced, not called with "&": a child scope would hide the variables the
                // command sets, and the success message reports them.
                + "try { . { " + command + " } *> $null; " //$NON-NLS-1$
                + "Write-Output \"OK: " + successMessage + "\" } " //$NON-NLS-1$ //$NON-NLS-2$
                + "catch { Write-Output \"FAILED: $($_.Exception.Message)\"; exit 1 }"); //$NON-NLS-1$
    }

    static String guestAgentCommand(String vmId) {
        return "python3 -c " + shellQuote(GUEST_AGENT_SCRIPT) + " " + shellQuote(vmId);
    }

    /**
     * The SSH client reports a non zero exit code without the output of the failed command, so the
     * host side error has to be taken from the captured standard error stream.
     */
    private String describeFailure(String message, ByteArrayOutputStream err) {
        String error = err.toString(StandardCharsets.UTF_8).trim();
        if (!error.isEmpty()) {
            log.error("Guest agent command on VM '{}' failed: {}", getVm().getName(), error);
        }
        String detail = lastLine(error);
        if (detail.isEmpty()) {
            return StringUtils.isBlank(message) ? "The guest agent command produced no output" : message;
        }
        return StringUtils.isBlank(message) ? detail : message + ": " + detail;
    }

    private static String lastLine(String value) {
        // Trailing newlines are the norm, and would otherwise make the last line an empty one.
        String trimmed = value.trim();
        int index = trimmed.lastIndexOf('\n');
        return index < 0 ? trimmed : trimmed.substring(index + 1).trim();
    }

    /**
     * Builds the command that reconfigures one adapter of the guest.
     *
     * <p>The adapter is located by its MAC address rather than by its name, because the name is the
     * localized Windows interface alias and differs per guest.
     *
     * <p>Both cmdlets that change the adapter return before the change has taken effect, so the
     * command waits for the adapter to actually reach the requested state and fails when it does
     * not. Enabling also clears DHCP and the previous address and default route, which would
     * otherwise leave the new address unusable.
     */
    /**
     * Disables the adapter, or brings it up on a lease or on an address of its own.
     *
     * <p>The two ways of being up are not two ways of writing the same thing. A static address does
     * not take hold while the interface is still asking for a lease, and a lease does not arrive
     * while a manual address is sitting on the interface, so each has to take the other's
     * arrangement apart before making its own. Both then wait to see the result rather than
     * reporting the cmdlet that asked for it: {@code New-NetIPAddress} returns while the address is
     * still Tentative, and a lease takes as long as the server takes.</p>
     */
    static String networkCommand(boolean enabled, boolean dhcp, String macAddress,
            String ipAddress, String subnetMask, String gateway, String dnsServer) {
        String lookup = "$mac = \"" + normalizedMacAddress(macAddress) + "\"; " //$NON-NLS-1$ //$NON-NLS-2$
                + "$adapter = Get-NetAdapter | Where-Object " //$NON-NLS-1$
                + "{ ($_.MacAddress -replace \"[^0-9A-Fa-f]\", \"\") -eq $mac } | Select-Object -First 1; " //$NON-NLS-1$
                + "if (-not $adapter) { throw \"No network adapter with MAC address $mac was found\" }; " //$NON-NLS-1$
                + "$name = $adapter.Name; "; //$NON-NLS-1$
        if (!enabled) {
            return lookup
                    + "Disable-NetAdapter -Name $name -Confirm:$false; " //$NON-NLS-1$
                    + waitFor("(Get-NetAdapter -Name $name).Status -ne \"Up\"") //$NON-NLS-1$
                    + "if ((Get-NetAdapter -Name $name).Status -eq \"Up\") " //$NON-NLS-1$
                    + "{ throw \"$name is still up\" }"; //$NON-NLS-1$
        }
        String up = lookup
                + "Enable-NetAdapter -Name $name -Confirm:$false; " //$NON-NLS-1$
                + waitFor("(Get-NetAdapter -Name $name).Status -eq \"Up\"") //$NON-NLS-1$
                + "if ((Get-NetAdapter -Name $name).Status -ne \"Up\") " //$NON-NLS-1$
                + "{ throw \"$name did not come up\" }; " //$NON-NLS-1$
                // Whatever was arranged before goes first, whichever way round this is.
                + "Remove-NetRoute -InterfaceAlias $name -DestinationPrefix 0.0.0.0/0 " //$NON-NLS-1$
                + "-Confirm:$false -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + "Remove-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 " //$NON-NLS-1$
                + "-Confirm:$false -ErrorAction SilentlyContinue; "; //$NON-NLS-1$
        if (dhcp) {
            String leased = "Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 " //$NON-NLS-1$
                    + "-ErrorAction SilentlyContinue | Where-Object " //$NON-NLS-1$
                    + "{ $_.PrefixOrigin -eq \"Dhcp\" -and $_.AddressState -eq \"Preferred\" }"; //$NON-NLS-1$
            return up
                    + "Set-NetIPInterface -InterfaceAlias $name -Dhcp Enabled; " //$NON-NLS-1$
                    // The servers a lease carries are of no use while a static list overrides them.
                    + "Set-DnsClientServerAddress -InterfaceAlias $name -ResetServerAddresses; " //$NON-NLS-1$
                    + waitFor("(" + leased + ") -ne $null") //$NON-NLS-1$ //$NON-NLS-2$
                    + "if (-not (" + leased + ")) " //$NON-NLS-1$ //$NON-NLS-2$
                    + "{ throw \"$name asked for an address and was not given one\" }"; //$NON-NLS-1$
        }
        String assigned = "Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 " //$NON-NLS-1$
                + "-ErrorAction SilentlyContinue | Where-Object " //$NON-NLS-1$
                + "{ $_.IPAddress -eq \"" + ipAddress + "\" -and $_.AddressState -eq \"Preferred\" }"; //$NON-NLS-1$ //$NON-NLS-2$
        return up
                + "Set-NetIPInterface -InterfaceAlias $name -Dhcp Disabled; " //$NON-NLS-1$
                + "New-NetIPAddress -InterfaceAlias $name -IPAddress " + ipAddress //$NON-NLS-1$
                + " -PrefixLength " + prefixLength(subnetMask) //$NON-NLS-1$
                + " -DefaultGateway " + gateway + "; " //$NON-NLS-1$ //$NON-NLS-2$
                + dnsCommand(dnsServer)
                // A new address is Tentative until duplicate address detection clears it.
                + waitFor("(" + assigned + ") -ne $null") //$NON-NLS-1$ //$NON-NLS-2$
                + "if (-not (" + assigned + ")) " //$NON-NLS-1$ //$NON-NLS-2$
                + "{ throw \"" + ipAddress + " is not active on $name\" }"; //$NON-NLS-1$ //$NON-NLS-2$
    }

    /**
     * @return the step that sets the name servers, or nothing when none were given
     *
     * <p>Nothing rather than an empty list: clearing the servers on an interface that was given
     * none would take away whatever it already had, which is not what leaving a field blank asks
     * for.</p>
     */
    private static String dnsCommand(String dnsServer) {
        if (dnsServer == null || dnsServer.trim().isEmpty()) {
            return ""; //$NON-NLS-1$
        }
        StringBuilder servers = new StringBuilder();
        for (String server : dnsServer.split("[,\\s]+")) { //$NON-NLS-1$
            if (isIpv4(server)) {
                servers.append(servers.length() > 0 ? "," : "").append('"').append(server).append('"'); //$NON-NLS-1$ //$NON-NLS-2$
            }
        }
        if (servers.length() == 0) {
            return ""; //$NON-NLS-1$
        }
        return "Set-DnsClientServerAddress -InterfaceAlias $name -ServerAddresses " //$NON-NLS-1$
                + servers + "; "; //$NON-NLS-1$
    }

    /** Polls until the condition holds, giving up after {@link #GUEST_WAIT_SECONDS}. */
    private static String waitFor(String condition) {
        return "$deadline = (Get-Date).AddSeconds(" + GUEST_WAIT_SECONDS + "); " //$NON-NLS-1$ //$NON-NLS-2$
                + "while (-not (" + condition + ") -and (Get-Date) -lt $deadline) " //$NON-NLS-1$ //$NON-NLS-2$
                + "{ Start-Sleep -Milliseconds 500 }; "; //$NON-NLS-1$
    }

    /** Windows reports MAC addresses with dashes, the engine stores them with colons. */
    static String normalizedMacAddress(String macAddress) {
        return macAddress == null ? "" : macAddress.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
    }

    static boolean isMacAddress(String macAddress) {
        return macAddress != null && macAddress.matches("(?i)^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$");
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

    /**
     * Blocks, or allows, the command prompt inside the guest.
     *
     * <p>This menu used to apply a whitelist: allow {@code %WINDIR%}, {@code %PROGRAMFILES%} and a
     * folder of the administrator's choosing, and let the enabled collection deny the rest. It
     * could never do what it was being used for. {@code cmd.exe} lives in {@code %WINDIR%}, which
     * that policy allowed, so the whitelist applied, reported success, and the command prompt went
     * on opening - which reads from the dialog as AppLocker not working at all.</p>
     *
     * <p>So it is stated the other way round: everything is allowed and {@code cmd.exe} is denied.
     * A switch for one program decides that program, and leaves the fate of everything else on the
     * machine to whoever installed it.</p>
     */
    /** Refuses the command prompt to ordinary users, or gives it back. */
    static String cmdCommand(boolean blocked) {
        return blocked
                ? srpDeny(CMD_MARKER, "cmd.exe") //$NON-NLS-1$
                : srpRelease(CMD_MARKER);
    }

    /* Software Restriction Policies -------------------------------------------------------- */

    /**
     * Where Windows keeps Software Restriction Policies.
     *
     * <p>This is what enforces the two blocks, in place of AppLocker. AppLocker is a feature of the
     * Enterprise, Education and Server editions: set it on Pro and the policy is stored, reported
     * as applied, and then ignored, which is what "the whitelist is on and cmd.exe still opens"
     * turned out to be. Software Restriction Policies are in every edition, and they judge
     * {@code .cpl} and {@code .msc} files as well as programs, which AppLocker does not.</p>
     */
    private static final String SRP_KEY =
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers"; //$NON-NLS-1$

    /** Rules live under the level they assign. Zero is Disallowed. */
    private static final String SRP_RULES = SRP_KEY + "\\0\\Paths"; //$NON-NLS-1$

    /** 0x40000. Anything without a rule of its own runs, so the rules are the exceptions. */
    private static final String SRP_UNRESTRICTED = "262144"; //$NON-NLS-1$

    /**
     * 1: everyone except the local administrators.
     *
     * <p>The same choice the AppLocker rules made by denying {@code BUILTIN\Users} and allowing
     * SYSTEM: an administrator can still put the machine right, and nothing here can reach the
     * account the guest agent runs as. A policy that locked out the account that lifts it would
     * have no way back.</p>
     */
    private static final String SRP_SKIP_ADMINISTRATORS = "1"; //$NON-NLS-1$

    /** 1: every designated file type except libraries. Programs, .cpl and .msc are all in it. */
    private static final String SRP_ENFORCE = "1"; //$NON-NLS-1$

    /** What each menu writes in its rules, so that releasing one leaves the other's alone. */
    private static final String CMD_MARKER = "ovworks-cmd"; //$NON-NLS-1$
    private static final String MANAGEMENT_MARKER = "ovworks-management"; //$NON-NLS-1$

    /**
     * Refuses the named files to ordinary users.
     *
     * <p>Each name is written without a folder in front of it, which is a rule about the file
     * wherever it is rather than about one copy of it. Applying twice does not pile rules up: the
     * ones this menu wrote before are taken out first, found by the mark they carry.</p>
     */
    private static String srpDeny(String marker, String... names) {
        StringBuilder command = new StringBuilder(disableAppLocker());
        command.append("New-Item -Path '").append(SRP_KEY).append("' -Force | Out-Null; "); //$NON-NLS-1$ //$NON-NLS-2$
        command.append(setValue(SRP_KEY, "DefaultLevel", SRP_UNRESTRICTED, "DWord")); //$NON-NLS-1$ //$NON-NLS-2$
        command.append(setValue(SRP_KEY, "PolicyScope", SRP_SKIP_ADMINISTRATORS, "DWord")); //$NON-NLS-1$ //$NON-NLS-2$
        command.append(setValue(SRP_KEY, "TransparentEnabled", SRP_ENFORCE, "DWord")); //$NON-NLS-1$ //$NON-NLS-2$
        command.append("New-Item -Path '").append(SRP_RULES).append("' -Force | Out-Null; "); //$NON-NLS-1$ //$NON-NLS-2$
        command.append(removeMarkedRules(marker));
        command.append("foreach ($name in @(").append(quotedList(names)).append(")) { ") //$NON-NLS-1$ //$NON-NLS-2$
                .append("$rule = '").append(SRP_RULES).append("\\' + [guid]::NewGuid().ToString('B'); ") //$NON-NLS-1$ //$NON-NLS-2$
                .append("New-Item -Path $rule -Force | Out-Null; ") //$NON-NLS-1$
                // ExpandString, which is the type Windows writes: a rule may name a path with
                // environment variables in it, and a plain string would be taken literally.
                .append("Set-ItemProperty -Path $rule -Name ItemData -Type ExpandString -Value $name; ") //$NON-NLS-1$
                .append("Set-ItemProperty -Path $rule -Name SaferFlags -Type DWord -Value 0; ") //$NON-NLS-1$
                .append("Set-ItemProperty -Path $rule -Name Description -Type String -Value '") //$NON-NLS-1$
                .append(marker).append("'; }; "); //$NON-NLS-1$
        command.append(assertRulesWritten(marker, names.length));
        return command.toString();
    }

    /** Takes this menu's rules out again, and stops enforcing if it was the only one asking. */
    private static String srpRelease(String marker) {
        return beginRelease()
                + attempt("rules", removeMarkedRules(marker) //$NON-NLS-1$
                        // Only when nothing else is denied. Another menu's rules, or rules that
                        // were here before this dialog was ever used, are not this one's to drop.
                        + "if (@(Get-ChildItem -Path '" + SRP_RULES //$NON-NLS-1$
                        + "' -ErrorAction SilentlyContinue).Count -eq 0) { " //$NON-NLS-1$
                        + setValue(SRP_KEY, "TransparentEnabled", "0", "DWord") + "}") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
                + endRelease();
    }

    /** Finds the rules this menu wrote, by the mark in their description, and removes them. */
    private static String removeMarkedRules(String marker) {
        return "Get-ChildItem -Path '" + SRP_RULES + "' -ErrorAction SilentlyContinue " //$NON-NLS-1$ //$NON-NLS-2$
                + "| Where-Object { (Get-ItemProperty -Path $_.PSPath -Name Description " //$NON-NLS-1$
                + "-ErrorAction SilentlyContinue).Description -eq '" + marker + "' } " //$NON-NLS-1$ //$NON-NLS-2$
                + "| Remove-Item -Recurse -Force; "; //$NON-NLS-1$
    }

    /**
     * Fails unless the rules are really in the registry and really being enforced.
     *
     * <p>Writing a policy and enforcing one are different things, and the difference used to be
     * silent. It is read back rather than assumed, and the count has to match: a rule that did not
     * get written is a file that is not being refused, and nothing else would say so.</p>
     */
    private static String assertRulesWritten(String marker, int expected) {
        return "$written = @(Get-ChildItem -Path '" + SRP_RULES + "' " //$NON-NLS-1$ //$NON-NLS-2$
                + "| Where-Object { (Get-ItemProperty -Path $_.PSPath -Name Description " //$NON-NLS-1$
                + "-ErrorAction SilentlyContinue).Description -eq '" + marker + "' }).Count; " //$NON-NLS-1$ //$NON-NLS-2$
                + "if ($written -ne " + expected + ") { throw ('" + expected //$NON-NLS-1$ //$NON-NLS-2$
                + " rules were asked for and ' + $written + ' were written') }; " //$NON-NLS-1$
                + "if ((Get-ItemProperty -Path '" + SRP_KEY + "' -Name TransparentEnabled)" //$NON-NLS-1$ //$NON-NLS-2$
                + ".TransparentEnabled -ne 1) { throw 'the rules are stored but not enforced' }"; //$NON-NLS-1$
    }

    /**
     * Turns AppLocker off before the rules below are written.
     *
     * <p>Where AppLocker is configured, Software Restriction Policies are ignored. A guest that had
     * been through an earlier version of this dialog is carrying an AppLocker policy, so leaving it
     * in place would mean writing rules that Windows never consults - applied, and no change, for
     * the third time.
     */
    private static String disableAppLocker() {
        return "$xml = '" + clearPolicy() + "'; " //$NON-NLS-1$ //$NON-NLS-2$
                + "Set-Content -Path C:\\ovworks_clear_policy.xml -Value $xml; " //$NON-NLS-1$
                + "Set-AppLockerPolicy -XmlPolicy C:\\ovworks_clear_policy.xml " //$NON-NLS-1$
                + "-ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + "Stop-Service AppIDSvc -Force -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + setValue(APPIDSVC_KEY, "Start", APPIDSVC_MANUAL, "DWord"); //$NON-NLS-1$ //$NON-NLS-2$
    }

    /** @return the names as a PowerShell list of single quoted strings */
    private static String quotedList(String... names) {
        StringBuilder list = new StringBuilder();
        for (String name : names) {
            if (list.length() > 0) {
                list.append(','); //$NON-NLS-1$
            }
            list.append('\'').append(name).append('\'');
        }
        return list.toString();
    }

    /**
     * Blocks, or releases, the commands an ordinary user would use to undo the network and file
     * sharing policies this dialog applies.
     *
     * <p>Three things have to hold at once, because each on its own is easy to walk around: the
     * tools and the hosts that could stand in for them are refused, the server service that
     * publishes shares is stopped, and the settings pages that offer the same changes through a
     * window rather than a command line are hidden.
     *
     * <p>The refusing is done with Software Restriction Policies, which judge the settings pages
     * themselves - {@code firewall.cpl}, {@code wf.msc} - and not only the programs. It also needs
     * no list of what may run: the rules name what may not, so a guest goes on running whatever it
     * was installed to run, and there is no folder to register and nothing to break by forgetting
     * to.
     */
    static String managementCommandsCommand(boolean blocked) {
        if (!blocked) {
            // Every step is attempted. They are independent, and the one thing this must not do
            // is stop partway: the steps below re-enable file sharing and give the user back the
            // network settings pages, so abandoning them leaves the machine locked down by the
            // command that was asked to unlock it.
            return beginRelease()
                    + attempt("rules", removeMarkedRules(MANAGEMENT_MARKER) //$NON-NLS-1$
                            + "if (@(Get-ChildItem -Path '" + SRP_RULES //$NON-NLS-1$
                            + "' -ErrorAction SilentlyContinue).Count -eq 0) { " //$NON-NLS-1$
                            + setValue(SRP_KEY, "TransparentEnabled", "0", "DWord") + "}") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
                    + attempt("file sharing service", //$NON-NLS-1$
                            "Set-Service -Name LanmanServer -StartupType Automatic; " //$NON-NLS-1$
                                    + "Start-Service LanmanServer " //$NON-NLS-1$
                                    + "-ErrorAction SilentlyContinue") //$NON-NLS-1$
                    + attempt("network settings pages", //$NON-NLS-1$
                            removeValue(NETWORK_POLICY_KEY, "NC_LanProperties") //$NON-NLS-1$
                                    + removeValue(NETWORK_POLICY_KEY, "NC_LanChangeProperties") //$NON-NLS-1$
                                    + removeValue(EXPLORER_POLICY_KEY, "NoInplaceSharing") //$NON-NLS-1$
                                    + removeValue(EXPLORER_POLICY_KEY, "SettingsPageVisibility") //$NON-NLS-1$
                                    + setValue(EXPLORER_KEY, "SharingWizardOn", "1", "DWord")) //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                    + endRelease();
        }
        return srpDeny(MANAGEMENT_MARKER, blockedNames()) + "; " //$NON-NLS-1$
                // Without the server service there is nothing left to publish a share with.
                + "Set-Service -Name LanmanServer -StartupType Disabled; " //$NON-NLS-1$
                + "Stop-Service LanmanServer -Force -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + "New-Item -Path \"" + NETWORK_POLICY_KEY + "\" -Force | Out-Null; " //$NON-NLS-1$ //$NON-NLS-2$
                + setValue(NETWORK_POLICY_KEY, "NC_LanProperties", "0", "DWord") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                + setValue(NETWORK_POLICY_KEY, "NC_LanChangeProperties", "0", "DWord") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                + "New-Item -Path \"" + EXPLORER_POLICY_KEY + "\" -Force | Out-Null; " //$NON-NLS-1$ //$NON-NLS-2$
                + setValue(EXPLORER_POLICY_KEY, "NoInplaceSharing", "1", "DWord") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                + setValue(EXPLORER_POLICY_KEY, "SettingsPageVisibility", //$NON-NLS-1$
                        "hide:network;network-*", "String") //$NON-NLS-1$ //$NON-NLS-2$
                + setValue(EXPLORER_KEY, "SharingWizardOn", "0", "DWord"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    }

    /** Everything this block refuses: the command line tools, and the windows that do the same. */
    static String[] blockedNames() {
        String[] names = new String[BLOCKED_TOOLS.length + BLOCKED_SETTINGS_PAGES.length];
        System.arraycopy(BLOCKED_TOOLS, 0, names, 0, BLOCKED_TOOLS.length);
        System.arraycopy(BLOCKED_SETTINGS_PAGES, 0, names, BLOCKED_TOOLS.length,
                BLOCKED_SETTINGS_PAGES.length);
        return names;
    }

    private static final String NETWORK_POLICY_KEY =
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections"; //$NON-NLS-1$
    private static final String EXPLORER_POLICY_KEY =
            "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"; //$NON-NLS-1$
    private static final String EXPLORER_KEY =
            "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer"; //$NON-NLS-1$

    /** Where Windows keeps a service's start type, which is the only way to set this one. */
    private static final String APPIDSVC_KEY =
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\AppIDSvc"; //$NON-NLS-1$

    /** The values that key takes: 2 automatic, 3 manual, 4 disabled. */
    private static final String APPIDSVC_AUTOMATIC = "2"; //$NON-NLS-1$
    private static final String APPIDSVC_MANUAL = "3"; //$NON-NLS-1$

    /**
     * Sets how the AppLocker service starts.
     *
     * <p>Through the registry, because {@code Set-Service} and {@code sc config} cannot do it.
     * The Application Identity service is owned by TrustedInstaller and its security descriptor
     * does not grant SERVICE_CHANGE_CONFIG to administrators, so both of those return</p>
     *
     * <pre>Service 'Application Identity (AppIDSvc)' cannot be configured due to the following
     * error: Access is denied</pre>
     *
     * <p>even for a command running as SYSTEM. This is what Group Policy writes when the
     * Application Identity service is set to start automatically there, which is how Microsoft's
     * own AppLocker instructions have it done. Starting and stopping the service is a different
     * right and works, so those stay as they are.</p>
     */
    private static String appIdServiceStartType(String value) {
        return setValue(APPIDSVC_KEY, "Start", value, "DWord"); //$NON-NLS-1$ //$NON-NLS-2$
    }

    /**
     * Runs a step and remembers it if it fails, rather than abandoning the ones after it.
     *
     * <p>For releasing a block only. The steps that release one are independent, and the script
     * runs with {@code $ErrorActionPreference = "Stop"}: without this, a step that failed left
     * the file sharing service disabled and the network settings pages hidden, which is the
     * machine still locked down by a command whose whole purpose was to unlock it.</p>
     */
    private static String attempt(String label, String step) {
        return "try { " + step + " } catch { $failed += '" + label + "' }; "; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    }

    /** Opens a release script, which collects what it could not do instead of stopping. */
    private static String beginRelease() {
        return "$failed = @(); "; //$NON-NLS-1$
    }

    /** Closes one, failing the action only after everything that could be released has been. */
    private static String endRelease() {
        return "if ($failed.Count) { throw \"could not release: \" + ($failed -join ', ') }"; //$NON-NLS-1$
    }

    private static String setValue(String key, String name, String value, String type) {
        return "Set-ItemProperty -Path \"" + key + "\" -Name " + name //$NON-NLS-1$ //$NON-NLS-2$
                + " -Value \"" + value + "\" -Type " + type + "; "; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    }

    private static String removeValue(String key, String name) {
        return "Remove-ItemProperty -Path \"" + key + "\" -Name " + name //$NON-NLS-1$ //$NON-NLS-2$
                + " -ErrorAction SilentlyContinue; "; //$NON-NLS-1$
    }

    /**
     * A policy that enforces nothing, for every collection this class used to enable.
     *
     * <p>All that is left of the AppLocker policies: it is what turns off a policy an earlier
     * version of this dialog applied, so that the rules that replaced them are the ones Windows
     * consults.</p>
     */
    static String clearPolicy() {
        return "<AppLockerPolicy Version=\"1\">" //$NON-NLS-1$
                + "<RuleCollection Type=\"Exe\" EnforcementMode=\"NotConfigured\" />" //$NON-NLS-1$
                + "<RuleCollection Type=\"Dll\" EnforcementMode=\"NotConfigured\" />" //$NON-NLS-1$
                + "<RuleCollection Type=\"Script\" EnforcementMode=\"NotConfigured\" />" //$NON-NLS-1$
                + "</AppLockerPolicy>"; //$NON-NLS-1$
    }

    private static String guestExecRequest(String path, List<String> arguments) {
        StringBuilder args = new StringBuilder();
        for (String argument : arguments) {
            if (args.length() > 0) {
                args.append(',');
            }
            args.append('"').append(jsonEscape(argument)).append('"');
        }
        // The QEMU guest agent schema names the argument list "arg", not "args".
        return "{\"execute\":\"guest-exec\",\"arguments\":{\"path\":\"" + jsonEscape(path)
                + "\",\"arg\":[" + args + "],\"capture-output\":true}}";
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
        // A single quote has to end the quoted run, be passed as a double quoted quote, and reopen it.
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String decode(Object value) {
        if (value == null) {
            return "";
        }
        String text = new String(Base64.getDecoder().decode(value.toString()), StandardCharsets.UTF_8);
        return text.startsWith("\uFEFF") ? text.substring(1) : text;
    }
}
