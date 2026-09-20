package org.ovirt.engine.core.bll;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.EngineSSHClient;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.action.ExecuteVmGuestCommandParameters;
import org.ovirt.engine.core.common.businessentities.VDS;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.dao.VdsDao;
import org.ovirt.engine.core.utils.JsonHelper;

/** Executes an approved Windows batch file or network operation through the VM's QEMU guest agent. */
public class ExecuteVmGuestCommandCommand<T extends ExecuteVmGuestCommandParameters>
        extends VmOperationCommandBase<T> {
    /** Each attempt is a second, so this has to outlast the longest wait in the guest. */
    private static final int POLL_ATTEMPTS = 150;
    private static final long POLL_INTERVAL_MILLIS = 1000;
    private static final int MAX_CONSECUTIVE_AGENT_FAILURES = 3;
    private static final int AGENT_TIMEOUT_SECONDS = 120;
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
            // The hosts a user would reach for once the tools above are gone. Not cmd.exe: the
            // menu above is the switch for that one, and a name in both lists meant releasing one
            // menu left the other still refusing it - a block that will not come off.
            "powershell.exe", "powershell_ise.exe", "pwsh.exe", "wmic.exe",
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

    /** How far back a pass looks when the caller does not say. */
    private static final int DEFAULT_LOOKBACK_HOURS = 2;

    /**
     * The Audit Failure keyword, 0x10000000000000. Every refused logon, denied access and failed
     * privilege check carries it, whatever the level of the entry says - the security log records
     * all of its entries as informational, so the level tells nothing about how serious one is.
     */
    private static final long AUDIT_FAILURE_KEYWORD = 4503599627370496L;

    /**
     * Security entries that are recorded as successes and are still worth an engine event: the
     * audit trail being erased or reconfigured, and the accounts, group memberships and passwords
     * being changed underneath the engine.
     */
    private static final int[] SECURITY_EVENT_IDS = {
            1102, // the security log was cleared
            4719, // the system audit policy was changed
            4720, // a user account was created
            4722, // a user account was enabled
            4724, // an attempt was made to reset an account password
            4725, // a user account was disabled
            4726, // a user account was deleted
            4728, // a member was added to a security enabled global group
            4732, // a member was added to a security enabled local group
            4740  // a user account was locked out
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
     * How long a lease is waited for.
     *
     * <p>Longer than anything else here waits. A server answers in a moment or takes as long as it
     * takes, and fifteen seconds was calling a slow answer a failure. It still fits inside what
     * the engine waits for the command as a whole.</p>
     */
    private static final int DHCP_WAIT_SECONDS = 45;

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
        describeRequest();
    }

    /**
     * Says what was asked for, in the words the engine event will use.
     *
     * <p>Here rather than where the request is carried out, because an event is written for a
     * request that never reached the guest too - a VM that went down, a host that could not be
     * reached - and "what was attempted" is the part of that event worth having.</p>
     */
    private void describeRequest() {
        T parameters = getParameters();
        if (parameters.getNetworkEnabled() != null) {
            addCustomValue("GuestAdapter", StringUtils.defaultString(parameters.getMacAddress())); //$NON-NLS-1$
            addCustomValue("GuestSetting", networkSettingDescription(parameters)); //$NON-NLS-1$
        } else if (parameters.getFileSharingBlocked() != null) {
            addCustomValue("GuestSetting", //$NON-NLS-1$
                    parameters.getFileSharingBlocked() ? "blocked" : "allowed"); //$NON-NLS-1$ //$NON-NLS-2$
        } else if (parameters.getManagementCommandsBlocked() != null) {
            addCustomValue("GuestPolicy", "The network and file sharing commands"); //$NON-NLS-1$ //$NON-NLS-2$
            addCustomValue("GuestSetting", //$NON-NLS-1$
                    parameters.getManagementCommandsBlocked() ? "blocked" : "allowed"); //$NON-NLS-1$ //$NON-NLS-2$
        } else if (parameters.getCmdBlocked() != null) {
            addCustomValue("GuestPolicy", "The command prompt"); //$NON-NLS-1$ //$NON-NLS-2$
            addCustomValue("GuestSetting", //$NON-NLS-1$
                    parameters.getCmdBlocked() ? "blocked" : "allowed"); //$NON-NLS-1$ //$NON-NLS-2$
        } else if (!StringUtils.isBlank(parameters.getPath())) {
            addCustomValue("GuestSetting", parameters.getPath()); //$NON-NLS-1$
        }
    }

    private static String networkSettingDescription(ExecuteVmGuestCommandParameters parameters) {
        if (!Boolean.TRUE.equals(parameters.getNetworkEnabled())) {
            return "disabled"; //$NON-NLS-1$
        }
        if (Boolean.TRUE.equals(parameters.getDhcp())) {
            return "enabled, on a lease"; //$NON-NLS-1$
        }
        return "enabled, with " + StringUtils.defaultString(parameters.getIpAddress()); //$NON-NLS-1$
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return auditLogTypeOf(getParameters(), getSucceeded());
    }

    /**
     * The engine event this request is recorded as.
     *
     * <p>One per thing the security dialog does, so that the event list says which of them was
     * done rather than that something was. The pass the guest event collector makes is recorded
     * as nothing at all: it runs against every Windows VM every few minutes and reports what it
     * finds and what it cannot read on its own, and an event for each poll would drown both.</p>
     */
    static AuditLogType auditLogTypeOf(ExecuteVmGuestCommandParameters parameters, boolean succeeded) {
        if (Boolean.TRUE.equals(parameters.getCriticalEventsRequested())) {
            return AuditLogType.UNASSIGNED;
        }
        if (Boolean.TRUE.equals(parameters.getGuestEventsRequested())) {
            return succeeded ? AuditLogType.VM_GUEST_EVENTS_VIEWED : AuditLogType.VM_GUEST_EVENTS_VIEW_FAILED;
        }
        if (parameters.getNetworkEnabled() != null) {
            return succeeded
                    ? AuditLogType.VM_GUEST_NETWORK_SETTINGS_APPLIED
                    : AuditLogType.VM_GUEST_NETWORK_SETTINGS_FAILED;
        }
        if (parameters.getFileSharingBlocked() != null) {
            return succeeded
                    ? AuditLogType.VM_GUEST_FILE_SHARING_POLICY_APPLIED
                    : AuditLogType.VM_GUEST_FILE_SHARING_POLICY_FAILED;
        }
        if (parameters.getManagementCommandsBlocked() != null || parameters.getCmdBlocked() != null) {
            return succeeded
                    ? AuditLogType.VM_GUEST_COMMAND_POLICY_APPLIED
                    : AuditLogType.VM_GUEST_COMMAND_POLICY_FAILED;
        }
        return succeeded
                ? AuditLogType.VM_GUEST_SCRIPT_EXECUTED
                : AuditLogType.VM_GUEST_SCRIPT_EXECUTION_FAILED;
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
                + (getParameters().getCriticalEventsRequested() == null ? 0 : 1)
                + (getParameters().getManagementCommandsBlocked() == null ? 0 : 1);
        if (operationCount > 1) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_INVALID_CUSTOM_PROPERTIES_INVALID_SYNTAX);
        }
        if (getParameters().getGuestEventsRequested() != null
                || getParameters().getCriticalEventsRequested() != null
                || getParameters().getManagementCommandsBlocked() != null) {
            // Each asks for something named here rather than by the caller, so there is nothing
            // of the caller's to check. Left out, they fell through to the check below and were
            // refused for not naming a .bat file, which they never do.
            return true;
        }
        if (getParameters().getNetworkEnabled() != null) {
            if (!isMacAddress(getParameters().getMacAddress())) {
                return failValidation(EngineMessage.ACTION_TYPE_FAILED_INVALID_CUSTOM_PROPERTIES_INVALID_SYNTAX);
            }
            // Only when the adapter is being given an address of its own. One that asks for a
            // lease is not told any of these, and requiring them would refuse the request over
            // fields the screen does not even show.
            if (getParameters().getNetworkEnabled()
                    && !Boolean.TRUE.equals(getParameters().getDhcp())
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
            if (Boolean.TRUE.equals(getParameters().getCriticalEventsRequested())) {
                executable = "powershell.exe"; //$NON-NLS-1$
                arguments = powerShellOutputArguments(criticalGuestEventsCommand(
                        getParameters().getLookbackHours() == null
                                ? DEFAULT_LOOKBACK_HOURS
                                : getParameters().getLookbackHours(),
                        Boolean.TRUE.equals(getParameters().getSecurityEventsRequested())));
                format = ResultFormat.RAW;
            } else if (Boolean.TRUE.equals(getParameters().getGuestEventsRequested())) {
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
                        // The count comes from the script: the restrictions are per account, and
                        // a run that found no profile to write to would otherwise look the same
                        // as one that locked the machine down.
                        blocked
                                ? "network and file sharing commands are blocked " //$NON-NLS-1$
                                        + "($($roots.Count) profiles)" //$NON-NLS-1$
                                : "network and file sharing commands are allowed again " //$NON-NLS-1$
                                        + "($($roots.Count) profiles)"); //$NON-NLS-1$
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
                        describeOutcome(value, exitCode == 0);
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
            describeOutcome(e.getMessage(), false);
        }
    }

    /**
     * Says what the guest answered, in the words the engine event will use.
     *
     * <p>A request for the event log is the one whose answer is not put in the event: what comes
     * back is the log itself, and an event holding a hundred of a guest's own lines would be
     * unreadable and would bury the rest of the list. How many lines came back is recorded
     * instead, which is what an audit trail wants of a read.</p>
     */
    private void describeOutcome(String value, boolean succeeded) {
        if (succeeded && Boolean.TRUE.equals(getParameters().getGuestEventsRequested())) {
            addCustomValue("GuestEventCount", Integer.toString(countEvents(value))); //$NON-NLS-1$
            return;
        }
        String line = value == null ? "" : lastLine(value); //$NON-NLS-1$
        if (line.length() > AUDITED_RESULT_LENGTH) {
            line = line.substring(0, AUDITED_RESULT_LENGTH);
        }
        addCustomValue("GuestResult", line); //$NON-NLS-1$
    }

    static int countEvents(String output) {
        if (StringUtils.isBlank(output)) {
            return 0;
        }
        int events = 0;
        for (String line : output.split("\n")) { //$NON-NLS-1$
            if (!StringUtils.isBlank(line)) {
                events++;
            }
        }
        return events;
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
    /**
     * What has gone seriously wrong inside the guest, and what its security log has to say,
     * since a point in time.
     *
     * <p>Three questions rather than one, because the logs do not agree on what serious means.
     * The System and Application logs grade themselves, so levels one and two - Critical and
     * Error - are taken from them; everything below is what the guest does all day, and the list
     * the dialog shows is mostly this engine asking it things. The security log grades nothing:
     * it records a refused logon and an erased audit trail alike as informational. What is taken
     * from it is the Audit Failure keyword, which every refusal carries, and the successful
     * entries that change the audit trail or the accounts themselves.</p>
     *
     * <p>The level and the event identifier are reported as numbers, and the time in UTC in the
     * round trip format. The display name and the local format are written in the language and
     * calendar of the guest, so an engine that decided anything from them would decide it
     * differently for a Korean guest than for an English one.</p>
     *
     * <p>Each line carries the record number it had in the guest, which is what lets the same
     * event be recognised across passes and recorded once. Sorted oldest first, so that a pass
     * that is cut short leaves a run with no holes in it rather than a scattering.</p>
     *
     * <p>A log that holds nothing matching is an error to Get-WinEvent, not an empty answer. That
     * one error is let go by its identifier, which is not translated; every other one - a security
     * log this guest will not hand over, above all - is left to fail the command, so that being
     * unable to read is not mistaken for having nothing to read.</p>
     */
    static String criticalGuestEventsCommand(int lookbackHours, boolean includeSecurityLog) {
        StringBuilder filters = new StringBuilder("$filters = @(") //$NON-NLS-1$
                .append("@{ LogName = @(\"System\", \"Application\"); ") //$NON-NLS-1$
                .append("Level = @(1, 2); StartTime = $start }"); //$NON-NLS-1$
        if (includeSecurityLog) {
            filters.append(", @{ LogName = \"Security\"; Keywords = [long]") //$NON-NLS-1$
                    .append(AUDIT_FAILURE_KEYWORD)
                    .append("; StartTime = $start }") //$NON-NLS-1$
                    .append(", @{ LogName = \"Security\"; Id = @(") //$NON-NLS-1$
                    .append(join(SECURITY_EVENT_IDS))
                    .append("); StartTime = $start }"); //$NON-NLS-1$
        }
        filters.append("); "); //$NON-NLS-1$
        return "$start = (Get-Date).AddHours(-" + lookbackHours + "); " //$NON-NLS-1$ //$NON-NLS-2$
                + filters
                + "$events = @(); " //$NON-NLS-1$
                + "foreach ($filter in $filters) { " //$NON-NLS-1$
                + "try { $events += @(Get-WinEvent -FilterHashtable $filter -MaxEvents " //$NON-NLS-1$
                + CRITICAL_EVENT_LIMIT + " -ErrorAction Stop) } " //$NON-NLS-1$
                + "catch { if ($_.FullyQualifiedErrorId -notlike \"NoMatchingEventsFound*\") { throw } } }; " //$NON-NLS-1$
                // A record number belongs to one log, so the pair is what identifies an event.
                + "$events | Sort-Object -Property LogName, RecordId -Unique " //$NON-NLS-1$
                + "| Sort-Object -Property TimeCreated | Select-Object -First " + CRITICAL_EVENT_LIMIT //$NON-NLS-1$
                + " | ForEach-Object { " //$NON-NLS-1$
                + "$message = \"\"; " //$NON-NLS-1$
                + "if ($_.Message) { $message = ($_.Message -replace \"[`r`n`t]+\", \" \").Trim() }; " //$NON-NLS-1$
                + "if ($message.Length -gt " + CRITICAL_EVENT_MESSAGE_LENGTH //$NON-NLS-1$
                + ") { $message = $message.Substring(0, " + CRITICAL_EVENT_MESSAGE_LENGTH + ") }; " //$NON-NLS-1$ //$NON-NLS-2$
                + "$source = \"\"; " //$NON-NLS-1$
                + "if ($_.ProviderName) " //$NON-NLS-1$
                + "{ $source = ($_.ProviderName -replace \"[`r`n`t]+\", \" \").Trim() }; " //$NON-NLS-1$
                + "$time = \"\"; " //$NON-NLS-1$
                + "if ($_.TimeCreated) { $time = $_.TimeCreated.ToUniversalTime().ToString(\"o\") }; " //$NON-NLS-1$
                + "\"{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}\" -f $_.RecordId, $_.LogName, " //$NON-NLS-1$
                + "[int]$_.Level, $source, [int]$_.Id, $time, $message }"; //$NON-NLS-1$
    }

    private static String join(int[] values) {
        return IntStream.of(values).mapToObj(Integer::toString).collect(Collectors.joining(", ")); //$NON-NLS-1$
    }

    /** How many a single pass brings back from one guest. */
    static final int CRITICAL_EVENT_LIMIT = 50;

    /** Enough of the message to know what happened, short enough to read in a list. */
    private static final int CRITICAL_EVENT_MESSAGE_LENGTH = 300;

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
                    // Turning DHCP on does not itself ask for anything. The interface may sit on
                    // what it had, or on nothing, until something makes it ask - which is what a
                    // renew is. Through WMI rather than ipconfig, which this dialog's other menu
                    // may have refused by then.
                    + "Get-CimInstance Win32_NetworkAdapterConfiguration " //$NON-NLS-1$
                    + "-Filter \"InterfaceIndex=$($adapter.ifIndex)\" " //$NON-NLS-1$
                    + "| Invoke-CimMethod -MethodName RenewDHCPLease " //$NON-NLS-1$
                    + "-ErrorAction SilentlyContinue | Out-Null; " //$NON-NLS-1$
                    + waitFor(DHCP_WAIT_SECONDS, "(" + leased + ") -ne $null") //$NON-NLS-1$ //$NON-NLS-2$
                    + "if (-not (" + leased + ")) { " //$NON-NLS-1$ //$NON-NLS-2$
                    // 169.254 is what Windows gives an interface that asked and got no answer.
                    // Saying so is the difference between a fault to look into and a network with
                    // no DHCP server on it, which is not something this dialog can fix.
                    + "$selfAssigned = Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 " //$NON-NLS-1$
                    + "-ErrorAction SilentlyContinue " //$NON-NLS-1$
                    + "| Where-Object { $_.IPAddress -like \"169.254.*\" }; " //$NON-NLS-1$
                    + "if ($selfAssigned) { throw \"$name got no answer from a DHCP server and " //$NON-NLS-1$
                    + "gave itself $($selfAssigned.IPAddress). There is no DHCP server on this " //$NON-NLS-1$
                    + "network, or it did not answer in " + DHCP_WAIT_SECONDS + " seconds.\" }; " //$NON-NLS-1$ //$NON-NLS-2$
                    + "throw \"$name asked for an address and was not given one\" }"; //$NON-NLS-1$
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
        return waitFor(GUEST_WAIT_SECONDS, condition);
    }

    /** Polls until the condition holds, giving up after the given number of seconds. */
    private static String waitFor(int seconds, String condition) {
        return "$deadline = (Get-Date).AddSeconds(" + seconds + "); " //$NON-NLS-1$ //$NON-NLS-2$
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
                ? srpDeny(CMD_MARKER, "cmd.exe") + RESTART_EXPLORER //$NON-NLS-1$
                : srpRelease(CMD_MARKER, "cmd.exe"); //$NON-NLS-1$
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
     * 0: everyone, the local administrators included.
     *
     * <p>Exempting them, which is what this used to do, meant a guest whose everyday account holds
     * administrator rights - most of them - was refused nothing at all, and the block reported
     * itself applied all the same.</p>
     *
     * <p>What keeps a way back is not this setting. Software Restriction Policies are documented
     * not to apply to a program run by the SYSTEM account, which is what the guest agent runs as,
     * so the command that lifts a block is outside them however wide this is set. It is checked
     * rather than trusted: see {@link #proveTheWayBack(String)}.</p>
     */
    private static final String SRP_ALL_USERS = "0"; //$NON-NLS-1$

    /** 1: every designated file type except libraries. Programs, .cpl and .msc are all in it. */
    private static final String SRP_ENFORCE = "1"; //$NON-NLS-1$

    /** What every mark this dialog writes begins with, so its own rules can be told from others. */
    private static final String MARKER_PREFIX = "ovworks-"; //$NON-NLS-1$

    /** What each menu writes in its rules, so that releasing one leaves the other's alone. */
    private static final String CMD_MARKER = MARKER_PREFIX + "cmd"; //$NON-NLS-1$
    private static final String MANAGEMENT_MARKER = MARKER_PREFIX + "management"; //$NON-NLS-1$

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
        command.append(setValue(SRP_KEY, "PolicyScope", SRP_ALL_USERS, "DWord")); //$NON-NLS-1$ //$NON-NLS-2$
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
        command.append(REFRESH_POLICY);
        command.append(assertRulesWritten(marker, names.length));
        command.append(proveTheWayBack(marker));
        // Explorer is left to the caller: it reads these once, when it starts, and a caller with
        // registry work still to do would have it read them as they were.
        return command.toString();
    }

    /**
     * Withdraws the rules that were just written unless the guest agent can still be reached.
     *
     * <p>The rules now cover the administrators, and one of the names on the management list is
     * the PowerShell the agent runs everything through. Software Restriction Policies are
     * documented not to apply to a program run by the SYSTEM account, so they should not touch it
     * - but a guest that is wrong about that would be a guest holding a block with nothing left
     * able to lift it, and no way in to find out. So it is tried: a fresh PowerShell is started,
     * the way the next command would start one, and has to come back with what it was told to
     * return. If it does not, the rules come out again and the dialog says why.</p>
     */
    private static String proveTheWayBack(String marker) {
        return "$probe = $null; " //$NON-NLS-1$
                + "try { $probe = Start-Process -FilePath " //$NON-NLS-1$
                + "\"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" " //$NON-NLS-1$
                + "-ArgumentList '-NoProfile','-NonInteractive','-Command','exit 7' " //$NON-NLS-1$
                + "-Wait -PassThru -WindowStyle Hidden -ErrorAction Stop } catch { $probe = $null }; " //$NON-NLS-1$
                + "if ($probe -eq $null -or $probe.ExitCode -ne 7) { " //$NON-NLS-1$
                + removeMarkedRules(marker)
                + stopEnforcingIfNothingIsDenied()
                + "throw 'the rules were taken out again: they would have refused the account this " //$NON-NLS-1$
                + "dialog works through, and nothing would have been able to lift them' }; "; //$NON-NLS-1$
    }

    /** Puts the machine back to having no policy at all, rather than one that denies nothing. */
    private static String stopEnforcingIfNothingIsDenied() {
        return "if (@(Get-ChildItem -Path '" + SRP_RULES //$NON-NLS-1$
                + "' -ErrorAction SilentlyContinue).Count -eq 0) { " //$NON-NLS-1$
                + "Remove-ItemProperty -Path '" + SRP_KEY + "' -Name TransparentEnabled " //$NON-NLS-1$ //$NON-NLS-2$
                + "-ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + "Remove-ItemProperty -Path '" + SRP_KEY + "' -Name PolicyScope " //$NON-NLS-1$ //$NON-NLS-2$
                + "-ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + "Remove-ItemProperty -Path '" + SRP_KEY + "' -Name DefaultLevel " //$NON-NLS-1$ //$NON-NLS-2$
                + "-ErrorAction SilentlyContinue }; "; //$NON-NLS-1$
    }

    /**
     * Asks Windows to read the policy again.
     *
     * <p>Without it the rules wait for the next sign-in, which is what "it only took effect after
     * I logged out" was. Bounded, and its failure is nobody's problem: it can ask whether to sign
     * out now, and a hidden window with no one at it would wait for an answer forever.</p>
     */
    private static final String REFRESH_POLICY =
            "$gp = Start-Process -FilePath \"$env:SystemRoot\\System32\\gpupdate.exe\" " //$NON-NLS-1$
                    + "-ArgumentList '/force' -PassThru -WindowStyle Hidden " //$NON-NLS-1$
                    + "-ErrorAction SilentlyContinue; " //$NON-NLS-1$
                    + "if ($gp) { $gp | Wait-Process -Timeout 30 -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                    + "if (-not $gp.HasExited) { $gp | Stop-Process -Force " //$NON-NLS-1$
                    + "-ErrorAction SilentlyContinue } }; "; //$NON-NLS-1$

    /**
     * Takes this menu's rules out again, and stops enforcing if it was the only one asking.
     *
     * <p>Its own rules, and any rule of this dialog's that names one of the same files. The two
     * menus used to both name {@code cmd.exe}, so a guest that was blocked by the older build is
     * carrying a rule for it under the other menu's mark - and lifting this block would leave it
     * refused by something this dialog put there and this dialog was no longer looking at.</p>
     */
    private static String srpRelease(String marker, String... names) {
        return beginRelease()
                + attempt("rules", removeThisDialogsRules(marker, names) //$NON-NLS-1$
                        + stopEnforcingIfNothingIsDenied()
                        + REFRESH_POLICY
                        + RESTART_EXPLORER)
                // Said after everything has been tried, so that a release which did not release
                // says so instead of reporting the success of having attempted it.
                + attempt("checking", assertNoneRefused(names) + checkedFurther(names)) //$NON-NLS-1$
                + endRelease();
    }

    /** The command prompt is worth starting to be sure of; a list of tools is not. */
    private static String checkedFurther(String... names) {
        return names.length == 1 && "cmd.exe".equals(names[0]) ? assertCmdRuns() : ""; //$NON-NLS-1$ //$NON-NLS-2$
    }

    /** Removes the rules this menu wrote, and this dialog's rules for the same files. */
    private static String removeThisDialogsRules(String marker, String... names) {
        return "$mine = @(" + quotedList(names) + "); " //$NON-NLS-1$ //$NON-NLS-2$
                + "Get-ChildItem -Path '" + SRP_RULES + "' -ErrorAction SilentlyContinue " //$NON-NLS-1$ //$NON-NLS-2$
                + "| Where-Object { $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + "($p.Description -like '" + MARKER_PREFIX + "*') -and " //$NON-NLS-1$ //$NON-NLS-2$
                + "(($p.Description -eq '" + marker + "') -or ($mine -contains $p.ItemData)) } " //$NON-NLS-1$ //$NON-NLS-2$
                + "| Remove-Item -Recurse -Force; "; //$NON-NLS-1$
    }

    /**
     * Fails unless nothing is left refusing the files this menu is about.
     *
     * <p>Checking that this menu's own rules are gone is not the same question, and answering the
     * easier one is how a release came to report success while the program went on being refused:
     * the other menu's rules, written by a build where both lists named the same file, were still
     * there. So every rule that is left is read, and any that names one of these files is the
     * answer.</p>
     *
     * <p>Whether an AppLocker policy is configured goes into the message as well. One of those
     * overrides all of this, and it is the other thing on this machine that can refuse a program
     * with the words the user is looking at.</p>
     */
    private static String assertNoneRefused(String... names) {
        return "$mine = @(" + quotedList(names) + "); $left = @(); $all = @(); " //$NON-NLS-1$ //$NON-NLS-2$
                + "Get-ChildItem -Path '" + SRP_RULES + "' -ErrorAction SilentlyContinue " //$NON-NLS-1$ //$NON-NLS-2$
                + "| ForEach-Object { $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + "if ($p.ItemData) { $all += ($p.ItemData + ' [' + $p.Description + ']'); " //$NON-NLS-1$
                + "if ($mine -contains $p.ItemData) { $left += $p.ItemData } } }; " //$NON-NLS-1$
                + "if ($left.Count) { " + appLockerState() //$NON-NLS-1$
                + "throw ('still refused: ' + ($left -join ', ') + '. rules in place: ' " //$NON-NLS-1$
                + "+ ($all -join ', ') + '. AppLocker policy configured: ' + $appLocker) }; "; //$NON-NLS-1$
    }

    /**
     * Fails unless the command prompt really starts.
     *
     * <p>The rules being gone and the program running are different things, and only one of them
     * is what the person in front of the guest is going to try. It is started the way anything
     * starts it and has to come back with what it was told to return, so that a block held
     * somewhere this dialog does not write - an AppLocker policy, most of all - is caught here
     * rather than by the user.</p>
     */
    private static String assertCmdRuns() {
        return "$probe = $null; " //$NON-NLS-1$
                + "try { $probe = Start-Process -FilePath \"$env:SystemRoot\\System32\\cmd.exe\" " //$NON-NLS-1$
                + "-ArgumentList '/c','exit 7' -Wait -PassThru -WindowStyle Hidden " //$NON-NLS-1$
                + "-ErrorAction Stop } catch { $probe = $null }; " //$NON-NLS-1$
                + "if ($probe -eq $null -or $probe.ExitCode -ne 7) { $all = @(); " //$NON-NLS-1$
                + "Get-ChildItem -Path '" + SRP_RULES + "' -ErrorAction SilentlyContinue " //$NON-NLS-1$ //$NON-NLS-2$
                + "| ForEach-Object { $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + "if ($p.ItemData) { $all += ($p.ItemData + ' [' + $p.Description + ']') } }; " //$NON-NLS-1$
                + appLockerState()
                + "throw ('cmd.exe is still refused. rules in place: ' " //$NON-NLS-1$
                + "+ $(if ($all.Count) { $all -join ', ' } else { 'none' }) " //$NON-NLS-1$
                + "+ '. AppLocker policy configured: ' + $appLocker) }"; //$NON-NLS-1$
    }

    /** Reads whether AppLocker has anything to say here, without letting the asking fail. */
    private static String appLockerState() {
        return "$appLocker = 'no'; " //$NON-NLS-1$
                + "try { if (Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop) " //$NON-NLS-1$
                + "{ $appLocker = 'yes' } } catch { $appLocker = 'unknown' }; "; //$NON-NLS-1$
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
                + ".TransparentEnabled -ne 1) { throw 'the rules are stored but not enforced' }; "; //$NON-NLS-1$
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
                    + attempt("rules", removeThisDialogsRules(MANAGEMENT_MARKER, blockedNames()) //$NON-NLS-1$
                            + stopEnforcingIfNothingIsDenied()
                            + REFRESH_POLICY)
                    + attempt("file sharing service", //$NON-NLS-1$
                            "Set-Service -Name LanmanServer -StartupType Automatic; " //$NON-NLS-1$
                                    + "Start-Service LanmanServer " //$NON-NLS-1$
                                    + "-ErrorAction SilentlyContinue") //$NON-NLS-1$
                    + attempt("network settings pages", //$NON-NLS-1$
                            forEachUserHive(
                                    removeEach(NETWORK_POLICY_SUBKEY, NETWORK_RESTRICTIONS)
                                            + removeEach(NETWORK_POLICY_SUBKEY, ADMIN_PROHIBITS)
                                            + removeEach(EXPLORER_POLICY_SUBKEY,
                                                    "NoNetConnectDisconnect", "NoInplaceSharing", //$NON-NLS-1$ //$NON-NLS-2$
                                                    "DisallowCpl") //$NON-NLS-1$
                                            + "Remove-Item -Path \"$root\\" + EXPLORER_POLICY_SUBKEY //$NON-NLS-1$
                                            + "\\DisallowCpl\" -Recurse -Force " //$NON-NLS-1$
                                            + "-ErrorAction SilentlyContinue; ") //$NON-NLS-1$
                                    + removeValue(EXPLORER_POLICY_KEY, "SettingsPageVisibility") //$NON-NLS-1$
                                    + setValue(EXPLORER_KEY, "SharingWizardOn", "1", "DWord") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                                    + RESTART_EXPLORER)
                    // Said after everything has been tried, so that a release which did not
                    // release says so rather than reporting that it attempted one.
                    + attempt("checking", assertNoneRefused(blockedNames())) //$NON-NLS-1$
                    + endRelease();
        }
        return srpDeny(MANAGEMENT_MARKER, blockedNames())
                // Without the server service there is nothing left to publish a share with.
                + "Set-Service -Name LanmanServer -StartupType Disabled; " //$NON-NLS-1$
                + "Stop-Service LanmanServer -Force -ErrorAction SilentlyContinue; " //$NON-NLS-1$
                + forEachUserHive(
                        newKey(NETWORK_POLICY_SUBKEY)
                                + denyEach(NETWORK_POLICY_SUBKEY, NETWORK_RESTRICTIONS)
                                + setInHive(NETWORK_POLICY_SUBKEY, ADMIN_PROHIBITS, "1") //$NON-NLS-1$
                                + newKey(EXPLORER_POLICY_SUBKEY)
                                // Both of these are about sharing rather than about addresses:
                                // mapping a drive, and sharing a folder from its own properties.
                                + setInHive(EXPLORER_POLICY_SUBKEY, "NoNetConnectDisconnect", "1") //$NON-NLS-1$ //$NON-NLS-2$
                                + setInHive(EXPLORER_POLICY_SUBKEY, "NoInplaceSharing", "1") //$NON-NLS-1$ //$NON-NLS-2$
                                // And the Control Panel items that are the way to the window.
                                + setInHive(EXPLORER_POLICY_SUBKEY, "DisallowCpl", "1") //$NON-NLS-1$ //$NON-NLS-2$
                                + hiddenControlPanelItems())
                + setValue(EXPLORER_POLICY_KEY, "SettingsPageVisibility", //$NON-NLS-1$
                        hiddenSettingsPages(), "String") //$NON-NLS-1$
                + setValue(EXPLORER_KEY, "SharingWizardOn", "0", "DWord") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                + RESTART_EXPLORER;
    }

    /**
     * What is no longer allowed in the Network Connections window.
     *
     * <p>The window itself cannot be refused by a rule about files. It is a folder of the shell,
     * reached from the Network and Sharing Center or from the address bar, and opening it loads no
     * {@code .cpl} at all - which is why the rules refusing {@code ncpa.cpl} left it opening as
     * before. What closes it is taking away what can be done inside it.</p>
     *
     * <p>Zero is what each of these takes to mean not allowed; one, or absent, allows it. That is
     * the way round Group Policy writes them, and it reads oddly next to
     * {@link #ADMIN_PROHIBITS}.</p>
     */
    private static final String[] NETWORK_RESTRICTIONS = {
            "NC_LanConnect",              // enabling or disabling a connection
            "NC_LanProperties",           // the Properties button
            "NC_LanChangeProperties",     // the addresses behind it
            "NC_AllowAdvancedTCPIPConfig", // and the Advanced dialog behind those
            "NC_AddRemoveComponents",     // adding or removing a protocol
            "NC_ChangeBindState",         // turning one on or off
            "NC_AdvancedSettings",        // the Advanced Settings menu
            "NC_RenameLanConnection",
            "NC_DeleteConnection"
    };

    /**
     * The one that makes the restrictions above reach an administrator.
     *
     * <p>Without it they are simply not applied to anyone in the Administrators group, which is
     * the account a guest is usually signed in as - so every one of them was being written, and
     * Properties went on opening. It is the reason the window looked untouched while the rules
     * refusing {@code netsh} plainly worked.</p>
     *
     * <p>One, not zero: this one is written the way it reads.</p>
     */
    private static final String ADMIN_PROHIBITS = "NC_EnableAdminProhibits"; //$NON-NLS-1$

    private static final String NETWORK_POLICY_SUBKEY =
            "Policies\\Microsoft\\Windows\\Network Connections"; //$NON-NLS-1$
    /**
     * Where Explorer's own restrictions live, under a hive's Software key.
     *
     * <p>Not under {@code Policies\Microsoft\Windows}, which is where the Network Connections
     * ones are and where these were being written - a key Windows does not have and nothing ever
     * reads. Under the machine hive this is
     * {@code HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer}, and under a
     * user's it is the same path from their Software key.</p>
     */
    private static final String EXPLORER_POLICY_SUBKEY =
            "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"; //$NON-NLS-1$

    /**
     * Runs the given steps against every hive these restrictions are read from.
     *
     * <p>They are user policies, and they were being written to the machine hive, where nothing
     * reads them. That is why the window went on opening and everything in it went on working
     * while the dialog reported the block applied.</p>
     *
     * <p>Every account that is logged on has its hive loaded and gets them. The default profile is
     * loaded to be written to as well, so that an account made after this runs starts with them
     * rather than without. The machine hive is written too: a few of these are read from there on
     * some builds, and a value nothing reads costs nothing.</p>
     *
     * <p>{@code $subkey} is what the steps are written against, and {@code $root} is prefixed to
     * it, so a step names the key once and is applied everywhere it belongs.</p>
     */
    private static String forEachUserHive(String steps) {
        return "$roots = @('HKLM:\\SOFTWARE'); $loaded = @(); " //$NON-NLS-1$
                + "Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" //$NON-NLS-1$
                + "\\ProfileList' -ErrorAction SilentlyContinue " //$NON-NLS-1$
                // Real accounts only: the service and well known SIDs have nobody behind them.
                + "| Where-Object { $_.PSChildName -match '^S-1-5-21-[0-9-]+$' } " //$NON-NLS-1$
                + "| ForEach-Object { $sid = $_.PSChildName; " //$NON-NLS-1$
                // Signed in, so the hive is already there and is the one being read.
                + "if (Test-Path \"Registry::HKEY_USERS\\$sid\") " //$NON-NLS-1$
                + "{ $roots += \"Registry::HKEY_USERS\\$sid\\Software\" } " //$NON-NLS-1$
                // Signed out, so it is a file, and it has to be opened to be written to. Without
                // this an account that was not signed in when the block was applied comes back
                // without it, which is most of them on a machine used by one person at a time.
                + "else { $hive = (Get-ItemProperty -Path $_.PSPath -Name ProfileImagePath " //$NON-NLS-1$
                + "-ErrorAction SilentlyContinue).ProfileImagePath; " //$NON-NLS-1$
                + "if ($hive -and (Test-Path \"$hive\\NTUSER.DAT\")) { " //$NON-NLS-1$
                + "reg load \"HKU\\" + HIVE_PREFIX + "$sid\" \"$hive\\NTUSER.DAT\" *> $null; " //$NON-NLS-1$ //$NON-NLS-2$
                + "if ($LASTEXITCODE -eq 0) { $loaded += \"" + HIVE_PREFIX + "$sid\"; " //$NON-NLS-1$ //$NON-NLS-2$
                + "$roots += \"Registry::HKEY_USERS\\" + HIVE_PREFIX + "$sid\\Software\" } } } }; " //$NON-NLS-1$ //$NON-NLS-2$
                // And the profile an account made after this is copied from.
                + "$default = \"$env:SystemDrive\\Users\\Default\\NTUSER.DAT\"; " //$NON-NLS-1$
                + "if (Test-Path $default) { reg load 'HKU\\" + HIVE_PREFIX + "default' $default *> $null; " //$NON-NLS-1$ //$NON-NLS-2$
                + "if ($LASTEXITCODE -eq 0) { $loaded += '" + HIVE_PREFIX + "default'; " //$NON-NLS-1$ //$NON-NLS-2$
                + "$roots += 'Registry::HKEY_USERS\\" + HIVE_PREFIX + "default\\Software' } }; " //$NON-NLS-1$ //$NON-NLS-2$
                + "foreach ($root in $roots) { " + steps + "}; " //$NON-NLS-1$ //$NON-NLS-2$
                // A hive stays locked while anything still holds a handle into it.
                + "[gc]::Collect(); " //$NON-NLS-1$
                + "foreach ($h in $loaded) { reg unload \"HKU\\$h\" *> $null }; "; //$NON-NLS-1$
    }

    /** What a hive this opens is named while it is open, so its own can be told from the rest. */
    private static final String HIVE_PREFIX = "ovworks_"; //$NON-NLS-1$

    /**
     * The Control Panel items that open the Network Connections window, or the firewall.
     *
     * <p>Listed by canonical name under a numbered subkey, which is the shape this one takes: the
     * value beside it says a list is in force, and the subkey is the list.</p>
     */
    private static String hiddenControlPanelItems() {
        String[] items = {
                "Microsoft.NetworkAndSharingCenter", //$NON-NLS-1$
                "Microsoft.WindowsFirewall", //$NON-NLS-1$
                "Microsoft.InternetOptions", //$NON-NLS-1$
        };
        StringBuilder steps = new StringBuilder(newKey(EXPLORER_POLICY_SUBKEY + "\\DisallowCpl")); //$NON-NLS-1$
        for (int i = 0; i < items.length; i++) {
            steps.append("Set-ItemProperty -Path \"$root\\").append(EXPLORER_POLICY_SUBKEY) //$NON-NLS-1$
                    .append("\\DisallowCpl\" -Name '").append(i + 1) //$NON-NLS-1$
                    .append("' -Value '").append(items[i]).append("' -Type String; "); //$NON-NLS-1$ //$NON-NLS-2$
        }
        return steps.toString();
    }

    /**
     * The Settings pages that lead to the same changes.
     *
     * <p>Named one by one. This value takes a list of pages and not a pattern, so the
     * {@code network-*} that was here matched nothing at all and the Settings app went on
     * offering every one of them.</p>
     */
    private static String hiddenSettingsPages() {
        return "hide:network;network-status;network-ethernet;network-wifi;network-wifisettings;" //$NON-NLS-1$
                + "network-cellular;network-mobilehotspot;network-airplanemode;network-datausage;" //$NON-NLS-1$
                + "network-vpn;network-dialup;network-directaccess;network-proxy;" //$NON-NLS-1$
                + "network-advancedsettings"; //$NON-NLS-1$
    }

    private static String newKey(String subkey) {
        return "New-Item -Path \"$root\\" + subkey + "\" -Force | Out-Null; "; //$NON-NLS-1$ //$NON-NLS-2$
    }

    private static String setInHive(String subkey, String name, String value) {
        return "Set-ItemProperty -Path \"$root\\" + subkey + "\" -Name " + name //$NON-NLS-1$ //$NON-NLS-2$
                + " -Value " + value + " -Type DWord; "; //$NON-NLS-1$ //$NON-NLS-2$
    }

    /** Zero is what these take to mean "not allowed"; one, or absent, is allowed. */
    private static String denyEach(String subkey, String... names) {
        StringBuilder steps = new StringBuilder();
        for (String name : names) {
            steps.append(setInHive(subkey, name, "0")); //$NON-NLS-1$
        }
        return steps.toString();
    }

    private static String removeEach(String subkey, String... names) {
        StringBuilder steps = new StringBuilder();
        for (String name : names) {
            steps.append("Remove-ItemProperty -Path \"$root\\").append(subkey) //$NON-NLS-1$
                    .append("\" -Name ").append(name) //$NON-NLS-1$
                    .append(" -ErrorAction SilentlyContinue; "); //$NON-NLS-1$
        }
        return steps.toString();
    }

    /**
     * Explorer reads these once, when it starts.
     *
     * <p>Without this the restrictions take hold at the next sign-in, and in the meantime the
     * window goes on working - which is the block reporting success and changing nothing, the
     * thing this dialog has been wrong about too often already.</p>
     */
    private static final String RESTART_EXPLORER =
            "Get-Process explorer -ErrorAction SilentlyContinue " //$NON-NLS-1$
                    + "| Stop-Process -Force -ErrorAction SilentlyContinue; "; //$NON-NLS-1$

    /** Everything this block refuses: the command line tools, and the windows that do the same. */
    static String[] blockedNames() {
        String[] names = new String[BLOCKED_TOOLS.length + BLOCKED_SETTINGS_PAGES.length];
        System.arraycopy(BLOCKED_TOOLS, 0, names, 0, BLOCKED_TOOLS.length);
        System.arraycopy(BLOCKED_SETTINGS_PAGES, 0, names, BLOCKED_TOOLS.length,
                BLOCKED_SETTINGS_PAGES.length);
        return names;
    }

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
