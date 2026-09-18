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
    /** AppLocker denies these to ordinary users; each is a way to change the network or a share. */
    private static final String[] BLOCKED_TOOLS = {
            "netsh.exe", "netcfg.exe", "ipconfig.exe", "route.exe", "arp.exe", "netstat.exe",
            "net.exe", "net1.exe",
            // The hosts an ordinary user would reach for once the tools above are gone.
            "powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe", "wmic.exe",
            "cscript.exe", "wscript.exe", "mshta.exe",
            "reg.exe", "regedit.exe", "control.exe", "rundll32.exe", "mmc.exe"
    };

    /**
     * Control Panel applets that change the network, the firewall, or what the machine trusts.
     *
     * <p>None of them is a program. A {@code .cpl} is a library, and {@code control.exe} is what
     * loads it, so an executable rule never sees one: the whitelist can be enforcing and
     * {@code firewall.cpl} still opens, because what ran was {@code control.exe} out of an allowed
     * folder. They are denied in the DLL collection instead, which is the collection the loader
     * consults.</p>
     *
     * <p>Named one by one rather than denying every {@code .cpl}. The applets that are left -
     * display, sound, mouse, date and time - change nothing a user could not change anyway, and
     * taking them away costs the user something for no gain.</p>
     */
    private static final String[] BLOCKED_CONTROL_PANEL_APPLETS = {
            "firewall.cpl",   // Windows Defender Firewall
            "ncpa.cpl",       // Network Connections: an adapter is disabled or readdressed here
            "inetcpl.cpl",    // Internet Options, which is where the proxy is set
            "wscui.cpl",      // Security and Maintenance
            "sysdm.cpl",      // System Properties: remote desktop, the computer name
            "appwiz.cpl",     // Programs and Features, which turns Windows features on and off
            "hdwwiz.cpl"      // Device Manager: the network adapter can be removed here
    };

    /**
     * Folders under %WINDIR% that ordinary users can write to. They fall inside the allowed
     * %WINDIR% path, so without these rules a user could drop a copy of a blocked tool, or a
     * script, into one of them and run it anyway.
     */
    private static final String[] WRITABLE_SYSTEM_FOLDERS = {
            "%WINDIR%\\Temp\\*", "%WINDIR%\\Tasks\\*", "%WINDIR%\\Tracing\\*",
            "%WINDIR%\\Registration\\CRMLog\\*", "%WINDIR%\\debug\\WIA\\*",
            "%WINDIR%\\System32\\Tasks\\*", "%WINDIR%\\System32\\FxsTmp\\*",
            "%WINDIR%\\System32\\com\\dmp\\*", "%WINDIR%\\System32\\spool\\PRINTERS\\*",
            "%WINDIR%\\System32\\spool\\drivers\\color\\*",
            "%WINDIR%\\SysWOW64\\Tasks\\*", "%WINDIR%\\SysWOW64\\FxsTmp\\*",
            "%WINDIR%\\SysWOW64\\com\\dmp\\*"
    };

    /** Everyone. The rules that keep Windows itself working are written for this. */
    private static final String EVERYONE_SID = "S-1-1-0"; //$NON-NLS-1$
    /** BUILTIN\Users. Every interactive account is a member, the SYSTEM account is not. */
    private static final String USERS_SID = "S-1-5-32-545"; //$NON-NLS-1$
    /**
     * The SYSTEM account, which the guest agent runs as. It is allowed everything explicitly so
     * that blocking powershell.exe for users can never cut the engine off from the VM.
     */
    private static final String SYSTEM_SID = "S-1-5-18"; //$NON-NLS-1$

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
                arguments = powerShellArguments(
                        networkCommand(
                                enabled,
                                getParameters().getMacAddress(),
                                getParameters().getIpAddress(),
                                getParameters().getSubnetMask(),
                                getParameters().getGateway()),
                        enabled
                                ? "$name is up with " + getParameters().getIpAddress() //$NON-NLS-1$
                                : "$name is disabled"); //$NON-NLS-1$
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
                        managementCommandsCommand(blocked, getParameters().getAllowedAppPath()),
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
    static String networkCommand(
            boolean enabled, String macAddress, String ipAddress, String subnetMask, String gateway) {
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
        String assigned = "Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 " //$NON-NLS-1$
                + "-ErrorAction SilentlyContinue | Where-Object " //$NON-NLS-1$
                + "{ $_.IPAddress -eq \"" + ipAddress + "\" -and $_.AddressState -eq \"Preferred\" }"; //$NON-NLS-1$ //$NON-NLS-2$
        return lookup
                + "Enable-NetAdapter -Name $name -Confirm:$false; " //$NON-NLS-1$
                + waitFor("(Get-NetAdapter -Name $name).Status -eq \"Up\"") //$NON-NLS-1$
                + "if ((Get-NetAdapter -Name $name).Status -ne \"Up\") " //$NON-NLS-1$
                + "{ throw \"$name did not come up\" }; " //$NON-NLS-1$
                // A static address does not take hold while the interface still asks for a lease,
                // and the old address and default route would collide with the new ones.
                + "Set-NetIPInterface -InterfaceAlias $name -Dhcp Disabled; " //$NON-NLS-1$
                + "Remove-NetRoute -InterfaceAlias $name -DestinationPrefix 0.0.0.0/0 " //$NON-NLS-1$
                + "-Confirm:$false -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + "Remove-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 " //$NON-NLS-1$
                + "-Confirm:$false -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + "New-NetIPAddress -InterfaceAlias $name -IPAddress " + ipAddress //$NON-NLS-1$
                + " -PrefixLength " + prefixLength(subnetMask) //$NON-NLS-1$
                + " -DefaultGateway " + gateway + "; " //$NON-NLS-1$ //$NON-NLS-2$
                // A new address is Tentative until duplicate address detection clears it.
                + waitFor("(" + assigned + ") -ne $null") //$NON-NLS-1$ //$NON-NLS-2$
                + "if (-not (" + assigned + ")) " //$NON-NLS-1$ //$NON-NLS-2$
                + "{ throw \"" + ipAddress + " is not active on $name\" }"; //$NON-NLS-1$ //$NON-NLS-2$
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
    static String cmdCommand(boolean blocked) {
        if (!blocked) {
            return beginRelease()
                    + "$xml = '" + clearPolicy() + "'; " //$NON-NLS-1$ //$NON-NLS-2$
                    + attempt("policy", //$NON-NLS-1$
                            "Set-Content -Path " + CMD_POLICY_FILE + " -Value $xml; " //$NON-NLS-1$ //$NON-NLS-2$
                                    + "Set-AppLockerPolicy -XmlPolicy " + CMD_POLICY_FILE) //$NON-NLS-1$
                    + "Stop-Service AppIDSvc -Force -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                    + attempt("service start type", appIdServiceStartType(APPIDSVC_MANUAL)) //$NON-NLS-1$
                    + endRelease();
        }
        return appIdServiceStartType(APPIDSVC_AUTOMATIC)
                + "$xml = '" + cmdPolicy() + "'; " //$NON-NLS-1$ //$NON-NLS-2$
                + "Set-Content -Path " + CMD_POLICY_FILE + " -Value $xml; " //$NON-NLS-1$ //$NON-NLS-2$
                + "Set-AppLockerPolicy -XmlPolicy " + CMD_POLICY_FILE + "; " //$NON-NLS-1$ //$NON-NLS-2$
                + RELOAD_POLICY
                + assertDeniedToUsers("C:\\Windows\\System32\\cmd.exe"); //$NON-NLS-1$
    }

    private static final String CMD_POLICY_FILE = "C:\\ovworks_cmd_policy.xml"; //$NON-NLS-1$

    /**
     * A policy that denies the command prompt and decides nothing else.
     *
     * <p>Everything is allowed and one program is denied. The other way round - allow a few folders
     * and let the collection deny the rest - is a policy about every program on the machine, which
     * is not what a switch labelled {@code cmd.exe} should quietly turn into.</p>
     */
    private static String cmdPolicy() {
        RuleIds ids = new RuleIds();
        return "<AppLockerPolicy Version=\"1\">" //$NON-NLS-1$
                + "<RuleCollection Type=\"Dll\" EnforcementMode=\"NotConfigured\" />" //$NON-NLS-1$
                + "<RuleCollection Type=\"Script\" EnforcementMode=\"NotConfigured\" />" //$NON-NLS-1$
                + "<RuleCollection Type=\"Exe\" EnforcementMode=\"Enabled\">" //$NON-NLS-1$
                // The guest agent runs as SYSTEM and the command that lifts this arrives through it.
                + rule(ids, "Allow", SYSTEM_SID, "System", "*") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                + rule(ids, "Allow", EVERYONE_SID, "Everything", "*") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                // By name rather than by where it lives, so a copy in another folder is denied too.
                + rule(ids, "Deny", USERS_SID, "Cmd", "*\\cmd.exe") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                + "</RuleCollection></AppLockerPolicy>"; //$NON-NLS-1$
    }

    /**
     * Makes the Application Identity service read the policy that has just been written.
     *
     * <p>Starting it is not enough, and starting it is all this used to do. Where the service was
     * already running - the second time either menu is used, or any guest that had AppLocker on -
     * {@code Start-Service} does nothing at all and the service goes on enforcing what it read when
     * it started. A policy that applies without complaint and changes nothing is what that looks
     * like from the dialog.</p>
     */
    private static final String RELOAD_POLICY =
            "Restart-Service AppIDSvc -Force -ErrorAction SilentlyContinue; "; //$NON-NLS-1$

    /**
     * Fails unless the guest is really refusing the given program to ordinary users.
     *
     * <p>Three things leave a policy applied and nothing enforced, and not one of them raises an
     * error in the commands that applied it: the service does not run, this edition of Windows does
     * not enforce AppLocker at all - it is a feature of Enterprise, Education and Server, and a
     * policy set on Pro is simply ignored - or the rules do not decide the file they were written
     * for. The check is made against the effective policy rather than the file that was just
     * written, because the question is what the machine does, not what was asked of it.</p>
     *
     * <p>Worth the extra call: a block that reports success and blocks nothing is worse than one
     * that fails, because there is nothing to notice until someone relies on it.</p>
     */
    private static String assertDeniedToUsers(String path) {
        return "$status = (Get-Service AppIDSvc).Status; " //$NON-NLS-1$
                + "$os = (Get-CimInstance Win32_OperatingSystem).Caption; " //$NON-NLS-1$
                + "if ($status -ne 'Running') { throw ('Application Identity is ' + $status " //$NON-NLS-1$
                + "+ ' on ' + $os + ', so AppLocker enforces nothing') }; " //$NON-NLS-1$
                + "$decision = (Test-AppLockerPolicy -PolicyObject (Get-AppLockerPolicy -Effective)" //$NON-NLS-1$
                + " -Path '" + path + "' -User '" + USERS_SID + "').PolicyDecision; " //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                + "if ($decision -ne 'Denied') { throw ('" + path + " is ' + $decision " //$NON-NLS-1$ //$NON-NLS-2$
                + "+ ' for ordinary users on ' + $os) }"; //$NON-NLS-1$
    }

    /**
     * Blocks, or releases, the commands an ordinary user would use to undo the network and file
     * sharing policies this dialog applies.
     *
     * <p>Three things have to hold at once, because each on its own is easy to walk around:
     * AppLocker denies the tools and the hosts that could stand in for them, the server service
     * that publishes shares is stopped, and the settings pages that offer the same changes through
     * a window rather than a command line are hidden.
     *
     * <p>The AppLocker policy is written whole, so it replaces whatever policy is in place. The
     * executable whitelist writes the same policy, which means the one applied last wins; the
     * folder it allows is carried over here so that applying the block does not silently drop it.
     */
    static String managementCommandsCommand(boolean blocked, String allowedAppPath) {
        if (!blocked) {
            // Every step is attempted. They are independent, and the one thing this must not do
            // is stop partway: the steps below re-enable file sharing and give the user back the
            // network settings pages, so abandoning them leaves the machine locked down by the
            // command that was asked to unlock it.
            return beginRelease()
                    + "$xml = '" + clearPolicy() + "'; " //$NON-NLS-1$ //$NON-NLS-2$
                    + attempt("policy", //$NON-NLS-1$
                            "Set-Content -Path C:\\ovworks_clear_policy.xml -Value $xml; " //$NON-NLS-1$
                                    + "Set-AppLockerPolicy " //$NON-NLS-1$
                                    + "-XmlPolicy C:\\ovworks_clear_policy.xml") //$NON-NLS-1$
                    + "Stop-Service AppIDSvc -Force -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                    + attempt("AppLocker service start type", //$NON-NLS-1$
                            appIdServiceStartType(APPIDSVC_MANUAL))
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
        return appIdServiceStartType(APPIDSVC_AUTOMATIC)
                + "$xml = '" + blockPolicy(allowedAppPath) + "'; " //$NON-NLS-1$ //$NON-NLS-2$
                + "Set-Content -Path C:\\ovworks_block_policy.xml -Value $xml; " //$NON-NLS-1$
                + "Set-AppLockerPolicy -XmlPolicy C:\\ovworks_block_policy.xml; " //$NON-NLS-1$
                + RELOAD_POLICY
                // netsh.exe stands for the whole list: if the service is refusing it, it is
                // enforcing this policy, and if it is not, none of the rest is being enforced either.
                + assertDeniedToUsers("C:\\Windows\\System32\\netsh.exe") + "; " //$NON-NLS-1$ //$NON-NLS-2$
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
     * A policy that enforces nothing, for every collection this class ever enables.
     *
     * <p>The DLL collection belongs here as much as the other two: the whitelist enables it, and a
     * release that left it enforcing would go on denying libraries after the menu said the
     * whitelist was off - with no menu left that mentions libraries to turn it back off from.</p>
     */
    static String clearPolicy() {
        return "<AppLockerPolicy Version=\"1\">" //$NON-NLS-1$
                + "<RuleCollection Type=\"Exe\" EnforcementMode=\"NotConfigured\" />" //$NON-NLS-1$
                + "<RuleCollection Type=\"Dll\" EnforcementMode=\"NotConfigured\" />" //$NON-NLS-1$
                + "<RuleCollection Type=\"Script\" EnforcementMode=\"NotConfigured\" />" //$NON-NLS-1$
                + "</AppLockerPolicy>"; //$NON-NLS-1$
    }

    /**
     * An enabled rule collection denies whatever it does not allow, so enabling the script
     * collection is what stops a user from writing their own script to do the same work.
     */
    private static String blockPolicy(String allowedAppPath) {
        RuleIds ids = new RuleIds();
        StringBuilder policy = new StringBuilder("<AppLockerPolicy Version=\"1\">"); //$NON-NLS-1$
        for (String type : new String[] { "Exe", "Script", "Dll" }) { //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            policy.append("<RuleCollection Type=\"").append(type) //$NON-NLS-1$
                    .append("\" EnforcementMode=\"Enabled\">"); //$NON-NLS-1$
            policy.append(rule(ids, "Allow", SYSTEM_SID, "System", "*")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            policy.append(rule(ids, "Allow", EVERYONE_SID, "Windows", "%WINDIR%\\*")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            policy.append(rule(ids, "Allow", EVERYONE_SID, "Programs", "%PROGRAMFILES%\\*")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            if (isAllowedAppPath(allowedAppPath)) {
                policy.append(rule(ids, "Allow", EVERYONE_SID, "CustomApps", allowedAppPath)); //$NON-NLS-1$ //$NON-NLS-2$
            }
            for (String folder : WRITABLE_SYSTEM_FOLDERS) {
                policy.append(rule(ids, "Deny", USERS_SID, "Writable", folder)); //$NON-NLS-1$ //$NON-NLS-2$
            }
            if ("Exe".equals(type)) { //$NON-NLS-1$
                for (String tool : BLOCKED_TOOLS) {
                    // Matched by name anywhere, so a copy in another folder is blocked as well.
                    policy.append(rule(ids, "Deny", USERS_SID, "Tool", "*\\" + tool)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                }
            }
            if ("Dll".equals(type)) { //$NON-NLS-1$
                for (String applet : BLOCKED_CONTROL_PANEL_APPLETS) {
                    policy.append(rule(ids, "Deny", USERS_SID, "Applet", "*\\" + applet)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                }
            }
            policy.append("</RuleCollection>"); //$NON-NLS-1$
        }
        return policy.append("</AppLockerPolicy>").toString(); //$NON-NLS-1$
    }

    private static String rule(RuleIds ids, String action, String sid, String name, String path) {
        return "<FilePathRule Id=\"" + ids.next() + "\" Name=\"" + name + " " + xmlEscape(path) //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                + "\" Action=\"" + action + "\" UserOrGroupSid=\"" + sid + "\"><Conditions>" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                + "<FilePathCondition Path=\"" + xmlEscape(path) + "\" /></Conditions></FilePathRule>"; //$NON-NLS-1$ //$NON-NLS-2$
    }

    /** AppLocker wants a GUID per rule, and they only have to be unique within the policy. */
    private static class RuleIds {
        private int next;

        String next() {
            return String.format("%08x-0000-0000-0000-000000000000", ++next); //$NON-NLS-1$
        }
    }

    private static String xmlEscape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    static boolean isAllowedAppPath(String path) {
        if (path == null || !path.endsWith("\\*")) { //$NON-NLS-1$
            return false;
        }
        String directory = path.substring(0, path.length() - 2);
        return directory.matches("(?i)^[a-z]:\\\\[^\\r\\n'\"<>|?*]+$"); //$NON-NLS-1$
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
