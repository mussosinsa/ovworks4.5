package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ExecuteVmGuestCommandCommandTest {

    private static final String MAC = "00:1a:4a:16:01:51";

    @Test
    void shouldDisableTheAdapterThatCarriesTheGivenMacAddressAndWaitForItToStop() {
        String command = ExecuteVmGuestCommandCommand.networkCommand(false, MAC, null, null, null);

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.contains("$mac = \"001A4A160151\"")),
                () -> assertTrue(command.contains("($_.MacAddress -replace \"[^0-9A-Fa-f]\", \"\") -eq $mac")),
                () -> assertTrue(command.contains("Disable-NetAdapter -Name $name -Confirm:$false")),
                // The cmdlet returns before the adapter is down, so the state has to be waited for.
                () -> assertTrue(command.contains("while (-not ((Get-NetAdapter -Name $name).Status -ne \"Up\")")),
                () -> assertTrue(command.contains("throw \"$name is still up\"")));
    }

    @Test
    void shouldEnableAdapterWaitForItAndConfirmTheStaticAddressIsActive() {
        String command = ExecuteVmGuestCommandCommand.networkCommand(
                true, MAC, "192.168.1.100", "255.255.255.0", "192.168.1.1");

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.contains("Enable-NetAdapter -Name $name -Confirm:$false")),
                () -> assertTrue(command.contains("while (-not ((Get-NetAdapter -Name $name).Status -eq \"Up\")")),
                () -> assertTrue(command.contains("throw \"$name did not come up\"")),
                // A static address does not hold while the interface still asks for a lease.
                () -> assertTrue(command.contains("Set-NetIPInterface -InterfaceAlias $name -Dhcp Disabled")),
                () -> assertTrue(command.contains(
                        "Remove-NetRoute -InterfaceAlias $name -DestinationPrefix 0.0.0.0/0")),
                () -> assertTrue(command.contains("Remove-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4")),
                () -> assertTrue(command.contains("New-NetIPAddress -InterfaceAlias $name "
                        + "-IPAddress 192.168.1.100 -PrefixLength 24 -DefaultGateway 192.168.1.1")),
                // The address is Tentative until duplicate address detection clears it.
                () -> assertTrue(command.contains("$_.AddressState -eq \"Preferred\"")),
                () -> assertTrue(command.contains("throw \"192.168.1.100 is not active on $name\"")),
                () -> assertTrue(command.indexOf("Set-NetIPInterface")
                        > command.indexOf("Enable-NetAdapter")));
    }

    @Test
    void shouldReportOneLineOnSuccessAndTheReasonOnFailure() {
        java.util.List<String> arguments = ExecuteVmGuestCommandCommand.powerShellArguments(
                "Get-NetAdapter", "$name is up");

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertEquals(2, arguments.size()),
                () -> assertEquals("-Command", arguments.get(0)),
                () -> assertTrue(arguments.get(1).contains("$ErrorActionPreference = \"Stop\"")),
                // Everything the cmdlets print themselves is dropped.
                // Dot sourced so that $name set by the command is still in scope for the message.
                () -> assertTrue(arguments.get(1).contains("try { . { Get-NetAdapter } *> $null")),
                () -> assertTrue(arguments.get(1).contains("Write-Output \"OK: $name is up\"")),
                () -> assertTrue(arguments.get(1).contains(
                        "catch { Write-Output \"FAILED: $($_.Exception.Message)\"; exit 1 }")));
    }

    @Test
    void shouldDenyTheManagementToolsToOrdinaryUsersOnly() {
        String command = ExecuteVmGuestCommandCommand.managementCommandsCommand(
                true, "C:\\AllowedApps\\*");

        org.junit.jupiter.api.Assertions.assertAll(
                // Never to Everyone: the guest agent runs as SYSTEM and would deny itself
                // powershell.exe, which is how this dialog reaches the VM at all.
                () -> assertFalse(command.contains("Action=\"Deny\" UserOrGroupSid=\"S-1-1-0\"")),
                () -> assertTrue(command.contains("Action=\"Deny\" UserOrGroupSid=\"S-1-5-32-545\"")),
                () -> assertTrue(command.contains(
                        "Action=\"Allow\" UserOrGroupSid=\"S-1-5-18\"><Conditions>"
                                + "<FilePathCondition Path=\"*\" />")),
                // The tools themselves, and the hosts that could stand in for them.
                () -> assertTrue(command.contains("Path=\"*\\netsh.exe\"")),
                () -> assertTrue(command.contains("Path=\"*\\net.exe\"")),
                () -> assertTrue(command.contains("Path=\"*\\powershell.exe\"")),
                () -> assertTrue(command.contains("Path=\"*\\cmd.exe\"")),
                () -> assertTrue(command.contains("Path=\"*\\rundll32.exe\"")),
                // A copy dropped in a writable folder under the allowed %WINDIR% is denied too.
                () -> assertTrue(command.contains("Path=\"%WINDIR%\\Temp\\*\"")),
                // An enabled script collection denies the scripts it does not allow.
                () -> assertTrue(command.contains("<RuleCollection Type=\"Script\" EnforcementMode=\"Enabled\">")),
                // The folder the whitelist allows is carried over rather than dropped.
                () -> assertTrue(command.contains("Path=\"C:\\AllowedApps\\*\"")),
                // A command line alone is not enough to reach a share or the network settings.
                () -> assertTrue(command.contains("Set-Service -Name LanmanServer -StartupType Disabled")),
                () -> assertTrue(command.contains("SharingWizardOn")),
                () -> assertTrue(command.contains("NC_LanProperties")),
                () -> assertTrue(command.contains("SettingsPageVisibility")));
    }

    @Test
    void shouldPutEverythingBackWhenTheBlockIsReleased() {
        String command = ExecuteVmGuestCommandCommand.managementCommandsCommand(false, null);

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.contains(ExecuteVmGuestCommandCommand.clearPolicy())),
                // Through the registry: Set-Service cannot change this service's start type.
                () -> assertTrue(command.contains("AppIDSvc\" -Name Start -Value \"3\"")),
                () -> assertTrue(command.contains("Set-Service -Name LanmanServer -StartupType Automatic")),
                () -> assertTrue(command.contains("Remove-ItemProperty")),
                () -> assertTrue(command.contains("NC_LanProperties")),
                () -> assertTrue(command.contains("NoInplaceSharing")),
                () -> assertTrue(command.contains("SettingsPageVisibility")),
                () -> assertTrue(command.contains("SharingWizardOn")),
                () -> assertFalse(command.contains("Deny")));
    }

    @Test
    void shouldClearBothRuleCollectionsWhenTheWhitelistIsTurnedOff() {
        String command = ExecuteVmGuestCommandCommand.appLockerCommand(false, null);

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.contains("<RuleCollection Type=\"Exe\" EnforcementMode=\"NotConfigured\" />")),
                // The management block enables this one, so leaving it out would keep denying
                // scripts after the whitelist was turned off.
                () -> assertTrue(command.contains("<RuleCollection Type=\"Script\" EnforcementMode=\"NotConfigured\" />")));
    }

    @Test
    void shouldListRecentGuestEventsAsTabSeparatedLines() {
        String command = ExecuteVmGuestCommandCommand.guestEventsCommand();

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.startsWith("Get-WinEvent")),
                () -> assertTrue(command.contains("LogName = @(\"System\", \"Application\", \"Security\")")),
                () -> assertTrue(command.contains("StartTime = (Get-Date).AddHours(-24)")),
                () -> assertTrue(command.contains("-MaxEvents 100")),
                // An empty log is not a failure, and neither is a log this guest will not hand over.
                () -> assertTrue(command.contains("-ErrorAction SilentlyContinue")),
                // One event has to stay on one line for the dialog to split it back apart.
                () -> assertTrue(command.contains("-replace \"[`r`n`t]+\", \" \"")),
                () -> assertTrue(command.contains("\"{0}`t{1}`t{2}`t{3}\" -f")),
                () -> assertTrue(command.contains("$_.TimeCreated.ToString(\"yyyy-MM-dd HH:mm:ss\")")),
                () -> assertTrue(command.contains("$_.LogName, $_.LevelDisplayName, $message")));
    }

    @Test
    void shouldKeepTheOutputOfACommandWhoseOutputIsTheAnswer() {
        java.util.List<String> arguments =
                ExecuteVmGuestCommandCommand.powerShellOutputArguments("Get-WinEvent");

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertEquals("-Command", arguments.get(0)),
                // Nothing is suppressed here, unlike the commands that report a verdict.
                () -> assertFalse(arguments.get(1).contains("*> $null")),
                () -> assertTrue(arguments.get(1).contains("try { Get-WinEvent }")),
                () -> assertTrue(arguments.get(1).contains(
                        "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }")));
    }

    @Test
    void shouldSummarizeTheGuestOutputToASingleLine() {
        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertEquals("OK: win01 is up with 192.168.1.100",
                        ExecuteVmGuestCommandCommand.summarize(0, "OK: win01 is up with 192.168.1.100", "")),
                () -> assertEquals("FAILED: no adapter",
                        ExecuteVmGuestCommandCommand.summarize(1, "FAILED: no adapter", "")),
                // PowerShell ends its output with a newline.
                () -> assertEquals("OK: done",
                        ExecuteVmGuestCommandCommand.summarize(0, "OK: done\r\n", "")),
                // A guest that died before writing anything still gets a verdict.
                () -> assertEquals("boom", ExecuteVmGuestCommandCommand.summarize(1, "", "boom")),
                () -> assertEquals("OK", ExecuteVmGuestCommandCommand.summarize(0, "", "")),
                () -> assertEquals("FAILED: exit code 9",
                        ExecuteVmGuestCommandCommand.summarize(9, "", "")));
    }

    @Test
    void shouldNormalizeMacAddressesToTheWindowsForm() {
        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertEquals("001A4A160151",
                        ExecuteVmGuestCommandCommand.normalizedMacAddress("00:1a:4a:16:01:51")),
                () -> assertEquals("001A4A160151",
                        ExecuteVmGuestCommandCommand.normalizedMacAddress("00-1A-4A-16-01-51")),
                () -> assertEquals("", ExecuteVmGuestCommandCommand.normalizedMacAddress(null)));
    }

    @Test
    void shouldOnlyAcceptWellFormedMacAddresses() {
        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(ExecuteVmGuestCommandCommand.isMacAddress("00:1a:4a:16:01:51")),
                () -> assertTrue(ExecuteVmGuestCommandCommand.isMacAddress("00-1A-4A-16-01-51")),
                () -> assertFalse(ExecuteVmGuestCommandCommand.isMacAddress("001a4a160151")),
                () -> assertFalse(ExecuteVmGuestCommandCommand.isMacAddress("")),
                () -> assertFalse(ExecuteVmGuestCommandCommand.isMacAddress(null)));
    }

    @Test
    void shouldBlockInboundAndOutboundSmb() {
        assertEquals(
                "New-NetFirewallRule -DisplayName \"Block_SMB\" -Direction Inbound -Protocol TCP "
                        + "-LocalPort 139,445 -Action Block -ErrorAction SilentlyContinue; "
                        + "New-NetFirewallRule -DisplayName \"Block_SMB_Outbound\" -Direction Outbound "
                        + "-Protocol TCP -RemotePort 139,445 -Action Block -ErrorAction SilentlyContinue",
                ExecuteVmGuestCommandCommand.fileSharingCommand(true));
    }

    @Test
    void shouldRemoveInboundAndOutboundSmbBlocks() {
        assertEquals(
                "Remove-NetFirewallRule -DisplayName \"Block_SMB\" -ErrorAction SilentlyContinue; "
                        + "Remove-NetFirewallRule -DisplayName \"Block_SMB_Outbound\" "
                        + "-ErrorAction SilentlyContinue",
                ExecuteVmGuestCommandCommand.fileSharingCommand(false));
    }

    @Test
    void shouldApplyAppLockerWhitelistToSystemAndCustomFolders() {
        String command = ExecuteVmGuestCommandCommand.appLockerCommand(true, "C:\\AllowedApps\\*");

        org.junit.jupiter.api.Assertions.assertAll(
                () -> org.junit.jupiter.api.Assertions.assertTrue(
                        command.contains("AppIDSvc\" -Name Start -Value \"2\"")),
                () -> org.junit.jupiter.api.Assertions.assertTrue(command.contains("%WINDIR%\\*")),
                () -> org.junit.jupiter.api.Assertions.assertTrue(command.contains("%PROGRAMFILES%\\*")),
                () -> org.junit.jupiter.api.Assertions.assertTrue(command.contains("C:\\AllowedApps\\*")),
                () -> org.junit.jupiter.api.Assertions.assertTrue(command.contains("UserOrGroupSid=\"S-1-1-0\"")));
    }

    @Test
    void shouldResetAppLockerPolicyAndService() {
        String command = ExecuteVmGuestCommandCommand.appLockerCommand(false, null);

        org.junit.jupiter.api.Assertions.assertAll(
                () -> org.junit.jupiter.api.Assertions.assertTrue(command.contains("EnforcementMode=\"NotConfigured\"")),
                () -> org.junit.jupiter.api.Assertions.assertTrue(command.contains("Stop-Service AppIDSvc")),
                () -> org.junit.jupiter.api.Assertions.assertTrue(
                        command.contains("AppIDSvc\" -Name Start -Value \"3\"")));
    }

    @Test
    void shouldOnlyAcceptRestrictedWindowsFolderPatterns() {
        org.junit.jupiter.api.Assertions.assertAll(
                () -> org.junit.jupiter.api.Assertions.assertTrue(
                        ExecuteVmGuestCommandCommand.isAllowedAppPath("C:\\AllowedApps\\*")),
                () -> org.junit.jupiter.api.Assertions.assertFalse(
                        ExecuteVmGuestCommandCommand.isAllowedAppPath("C:\\AllowedApps\\tool.exe")),
                () -> org.junit.jupiter.api.Assertions.assertFalse(
                        ExecuteVmGuestCommandCommand.isAllowedAppPath("C:\\Allowed'Apps\\*")));
    }

    @Test
    void shouldRunGuestAgentCommandThroughTheVdsmLibvirtConnection() {
        String script = ExecuteVmGuestCommandCommand.GUEST_AGENT_SCRIPT;

        org.junit.jupiter.api.Assertions.assertAll(
                // VDSM sets auth_unix_rw="sasl", so the connection must carry its credentials.
                () -> assertTrue(script.contains("from vdsm.common import libvirtconnection")),
                () -> assertTrue(script.contains("libvirtconnection.get(killOnFailure=False)")),
                () -> assertTrue(script.contains("/etc/pki/vdsm/keys/libvirt_password")),
                () -> assertTrue(script.contains("vdsm@ovirt")),
                () -> assertTrue(script.contains("libvirt_qemu.qemuAgentCommand")),
                // The domain is addressed by UUID and the request arrives on the standard input.
                () -> assertTrue(script.contains("lookupByUUIDString(sys.argv[1])")),
                () -> assertTrue(script.contains("sys.stdin.read()")),
                () -> assertFalse(script.contains("virsh")));
    }

    @Test
    void shouldPassTheScriptAndVmIdAsSingleQuotedArguments() {
        String command = ExecuteVmGuestCommandCommand.guestAgentCommand(
                "11111111-2222-3333-4444-555555555555");

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.startsWith("python3 -c '")),
                () -> assertTrue(command.endsWith("'11111111-2222-3333-4444-555555555555'")),
                // A single quote in the script would break the shell quoting of the whole command.
                () -> assertFalse(ExecuteVmGuestCommandCommand.GUEST_AGENT_SCRIPT.contains("'")));
    }

    @Test
    void shouldMakePowerShellWriteUtf8WithoutAByteOrderMark() {
        java.util.List<String> arguments =
                ExecuteVmGuestCommandCommand.powerShellArguments("Get-NetAdapter", "done");

        // Without this the guest writes its ANSI code page and Korean output arrives as mojibake.
        assertTrue(arguments.get(1).startsWith(
                "$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; "));
    }

    @Test
    void shouldEscapeSingleQuotesWhenQuotingForTheShell() {
        assertEquals("'win'\"'\"'01'", ExecuteVmGuestCommandCommand.shellQuote("win'01"));
    }

    @Test
    void doesNotSetTheApplockerServiceStartTypeWithSetService() {
        // Set-Service and sc config both go through ChangeServiceConfig, and the Application
        // Identity service is owned by TrustedInstaller: administrators are not granted
        // SERVICE_CHANGE_CONFIG on it, so both come back with
        //   Service 'Application Identity (AppIDSvc)' cannot be configured due to the
        //   following error: Access is denied
        // even running as SYSTEM. The script runs with $ErrorActionPreference = "Stop", so that
        // error ended the script where it stood.
        for (String command : new String[] {
            ExecuteVmGuestCommandCommand.managementCommandsCommand(true, null), //$NON-NLS-1$
            ExecuteVmGuestCommandCommand.managementCommandsCommand(false, null), //$NON-NLS-1$
            ExecuteVmGuestCommandCommand.appLockerCommand(true, "C:\\AllowedApps\\*"), //$NON-NLS-1$
            ExecuteVmGuestCommandCommand.appLockerCommand(false, null), //$NON-NLS-1$
        }) {
            assertFalse(command.contains("Set-Service -Name AppIDSvc"), command); //$NON-NLS-1$
            assertTrue(command.contains(
                    "Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet" //$NON-NLS-1$
                            + "\\Services\\AppIDSvc\" -Name Start"), command); //$NON-NLS-1$
        }
    }

    @Test
    void asksForTheStartTypeThatMatchesWhatItIsDoing() {
        // 2 is automatic, 3 is manual. AppLocker enforces nothing once the service stops
        // starting with the machine, so blocking has to leave it at 2.
        assertTrue(ExecuteVmGuestCommandCommand.managementCommandsCommand(true, null)
                .contains("-Name Start -Value \"2\""), "blocking"); //$NON-NLS-1$ //$NON-NLS-2$
        assertTrue(ExecuteVmGuestCommandCommand.managementCommandsCommand(false, null)
                .contains("-Name Start -Value \"3\""), "releasing"); //$NON-NLS-1$ //$NON-NLS-2$
        assertTrue(ExecuteVmGuestCommandCommand.appLockerCommand(true, "C:\\A\\*") //$NON-NLS-1$
                .contains("-Name Start -Value \"2\""), "whitelist on"); //$NON-NLS-1$ //$NON-NLS-2$
        assertTrue(ExecuteVmGuestCommandCommand.appLockerCommand(false, null)
                .contains("-Name Start -Value \"3\""), "whitelist off"); //$NON-NLS-1$ //$NON-NLS-2$
    }

    @Test
    void asksForTheStartTypeBeforeItStartsTheService() {
        // Start-Service on a service whose start type is still Manual works, but the machine
        // comes back from its next reboot with AppLocker enforcing nothing.
        String command = ExecuteVmGuestCommandCommand.appLockerCommand(true, "C:\\A\\*"); //$NON-NLS-1$

        assertTrue(command.indexOf("-Name Start -Value \"2\"") //$NON-NLS-1$
                < command.indexOf("Start-Service AppIDSvc"), command); //$NON-NLS-1$
    }

    @Test
    void releasingAttemptsEveryStepRatherThanStoppingAtTheFirstFailure() {
        // The steps that release a block are what give the user back file sharing and the
        // network settings pages. Abandoning them halfway leaves the machine locked down by the
        // command that was asked to unlock it.
        String command = ExecuteVmGuestCommandCommand.managementCommandsCommand(false, null);

        assertTrue(command.startsWith("$failed = @(); "), command); //$NON-NLS-1$
        for (String step : new String[] {
            "policy", //$NON-NLS-1$
            "AppLocker service start type", //$NON-NLS-1$
            "file sharing service", //$NON-NLS-1$
            "network settings pages", //$NON-NLS-1$
        }) {
            assertTrue(command.contains("catch { $failed += '" + step + "' }"), step); //$NON-NLS-1$ //$NON-NLS-2$
        }
        // And it still fails the action, naming what it could not do.
        assertTrue(command.contains("if ($failed.Count) { throw"), command); //$NON-NLS-1$
        assertTrue(command.contains("could not release: "), command); //$NON-NLS-1$
    }

    @Test
    void releasingStillPutsBackEverythingBlockingTookAway() {
        String blocked = ExecuteVmGuestCommandCommand.managementCommandsCommand(true, null);
        String released = ExecuteVmGuestCommandCommand.managementCommandsCommand(false, null);

        assertTrue(blocked.contains("Set-Service -Name LanmanServer -StartupType Disabled"), //$NON-NLS-1$
                blocked);
        assertTrue(released.contains("Set-Service -Name LanmanServer -StartupType Automatic"), //$NON-NLS-1$
                released);
        assertTrue(released.contains("Start-Service LanmanServer"), released); //$NON-NLS-1$
        for (String value : new String[] {
            "NC_LanProperties", //$NON-NLS-1$
            "NC_LanChangeProperties", //$NON-NLS-1$
            "NoInplaceSharing", //$NON-NLS-1$
            "SettingsPageVisibility", //$NON-NLS-1$
        }) {
            assertTrue(blocked.contains(value), value);
            assertTrue(released.contains("Remove-ItemProperty") && released.contains(value), value); //$NON-NLS-1$
        }
        assertTrue(released.contains("SharingWizardOn -Value \"1\""), released); //$NON-NLS-1$
    }

    @Test
    void blockingStopsAtTheFirstFailureRatherThanApplyingHalfOfItself() {
        // The opposite rule from releasing, and for the same reason: a block that applied half
        // of itself and said so would be read as a block.
        String command = ExecuteVmGuestCommandCommand.managementCommandsCommand(true, null);

        assertFalse(command.contains("$failed"), command); //$NON-NLS-1$
    }

    /* The DLL collection the whitelist menu enforces */

    private static final String WHITELIST_PATH = "C:\\AllowedApps\\*"; //$NON-NLS-1$
    private static final String DLL_COLLECTION =
            "<RuleCollection Type=\"Dll\" EnforcementMode=\"Enabled\">"; //$NON-NLS-1$

    /** @return what the whitelist policy says between the given collection's tags */
    private static String collection(String command, String type) {
        String open = "<RuleCollection Type=\"" + type + "\" EnforcementMode=\"Enabled\">"; //$NON-NLS-1$ //$NON-NLS-2$
        int from = command.indexOf(open);
        assertTrue(from >= 0, type + " collection is not enforced: " + command); //$NON-NLS-1$
        return command.substring(from, command.indexOf("</RuleCollection>", from)); //$NON-NLS-1$
    }

    @Test
    void theWhitelistEnforcesLibrariesAsWellAsPrograms() {
        String command = ExecuteVmGuestCommandCommand.appLockerCommand(true, WHITELIST_PATH);

        assertTrue(command.contains(DLL_COLLECTION), command);
    }

    @Test
    void theWhitelistDeniesTheControlPanelAppletsThatChangeTheNetwork() {
        // A .cpl is a library, so an executable rule never judges it: control.exe is what runs,
        // and control.exe is in %WINDIR%, which the whitelist allows.
        String dll = collection(
                ExecuteVmGuestCommandCommand.appLockerCommand(true, WHITELIST_PATH), "Dll"); //$NON-NLS-1$

        for (String applet : new String[] {
            "firewall.cpl", "ncpa.cpl", "inetcpl.cpl", "wscui.cpl", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
            "sysdm.cpl", "appwiz.cpl", "hdwwiz.cpl", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        }) {
            assertTrue(dll.contains("Action=\"Deny\" UserOrGroupSid=\"S-1-5-32-545\"><Conditions>" //$NON-NLS-1$
                    + "<FilePathCondition Path=\"*\\" + applet + "\" />"), applet); //$NON-NLS-1$ //$NON-NLS-2$
        }
    }

    @Test
    void theAppletsAreLeftAloneInTheExecutableCollection() {
        // Denying them there would do nothing, and this menu changes what it said it changes.
        String exe = collection(
                ExecuteVmGuestCommandCommand.appLockerCommand(true, WHITELIST_PATH), "Exe"); //$NON-NLS-1$

        assertFalse(exe.contains("firewall.cpl"), exe); //$NON-NLS-1$
    }

    @Test
    void aLibraryRuleNeverStrandsTheVm() {
        // Every command that could turn this policy off again arrives through the guest agent,
        // which runs as SYSTEM. If a library rule could stop it, nothing could undo the whitelist.
        String dll = collection(
                ExecuteVmGuestCommandCommand.appLockerCommand(true, WHITELIST_PATH), "Dll"); //$NON-NLS-1$

        assertTrue(dll.contains("Action=\"Allow\" UserOrGroupSid=\"S-1-5-18\"><Conditions>" //$NON-NLS-1$
                + "<FilePathCondition Path=\"*\" />"), dll); //$NON-NLS-1$
    }

    @Test
    void theLibraryRulesCloseTheFoldersInsideWindowsThatUsersCanWriteTo() {
        // %WINDIR% is allowed whole, so without these a user drops a library in one of them and
        // has it loaded from a path the whitelist allows.
        String dll = collection(
                ExecuteVmGuestCommandCommand.appLockerCommand(true, WHITELIST_PATH), "Dll"); //$NON-NLS-1$

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(dll.contains("%WINDIR%\\Temp\\*"), dll), //$NON-NLS-1$
                () -> assertTrue(dll.contains("%WINDIR%\\System32\\Tasks\\*"), dll), //$NON-NLS-1$
                () -> assertTrue(dll.contains("%WINDIR%\\SysWOW64\\FxsTmp\\*"), dll)); //$NON-NLS-1$
    }

    @Test
    void theLibraryRulesAllowTheSameFoldersTheProgramRulesDo() {
        String dll = collection(
                ExecuteVmGuestCommandCommand.appLockerCommand(true, WHITELIST_PATH), "Dll"); //$NON-NLS-1$

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(dll.contains("%WINDIR%\\*"), dll), //$NON-NLS-1$
                () -> assertTrue(dll.contains("%PROGRAMFILES%\\*"), dll), //$NON-NLS-1$
                () -> assertTrue(dll.contains(WHITELIST_PATH), dll));
    }

    @Test
    void everyRuleInTheWhitelistPolicyHasAnIdOfItsOwn() {
        // The two collections are numbered from one source. Sharing an id between rules is what
        // makes AppLocker refuse the whole policy.
        String command = ExecuteVmGuestCommandCommand.appLockerCommand(true, WHITELIST_PATH);

        java.util.List<String> ids = new java.util.ArrayList<>();
        java.util.regex.Matcher found =
                java.util.regex.Pattern.compile("<FilePathRule Id=\"([^\"]+)\"").matcher(command); //$NON-NLS-1$
        while (found.find()) {
            ids.add(found.group(1));
        }

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(ids.size() > 20, "expected both collections: " + ids.size()), //$NON-NLS-1$
                () -> assertEquals(ids.size(), new java.util.HashSet<>(ids).size(), ids.toString()));
    }

    @Test
    void turningTheWhitelistOffStopsEnforcingLibrariesToo() {
        // A release that left this collection enforcing would go on denying libraries with no
        // menu left that mentions libraries to turn it off from.
        String command = ExecuteVmGuestCommandCommand.appLockerCommand(false, null);

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.contains(
                        "<RuleCollection Type=\"Dll\" EnforcementMode=\"NotConfigured\" />"), command), //$NON-NLS-1$
                () -> assertFalse(command.contains(DLL_COLLECTION), command));
    }

    @Test
    void theManagementBlockSaysThatItStopsEnforcingLibraries() {
        // It replaces the policy whole, so it does this either way; naming it is what stops the
        // next reader assuming the whitelist's library enforcement survives underneath.
        String command = ExecuteVmGuestCommandCommand.managementCommandsCommand(true, WHITELIST_PATH);

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.contains(
                        "<RuleCollection Type=\"Dll\" EnforcementMode=\"NotConfigured\" />"), command), //$NON-NLS-1$
                () -> assertFalse(command.contains(DLL_COLLECTION), command));
    }
}
