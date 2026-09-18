package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ExecuteVmGuestCommandCommandTest {

    private static final String MAC = "00:1a:4a:16:01:51";

    @Test
    void shouldDisableTheAdapterThatCarriesTheGivenMacAddressAndWaitForItToStop() {
        String command = ExecuteVmGuestCommandCommand.networkCommand(false, false, MAC, null, null, null, null);

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
                true, false, MAC, "192.168.1.100", "255.255.255.0", "192.168.1.1", "8.8.8.8");

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
    void shouldRefuseTheToolsTheSettingsPagesAndTheWaysAroundBoth() {
        String command = ExecuteVmGuestCommandCommand.managementCommandsCommand(true);

        org.junit.jupiter.api.Assertions.assertAll(
                // The tools themselves, and the hosts that could stand in for them.
                () -> assertTrue(command.contains("'netsh.exe'"), command),
                () -> assertTrue(command.contains("'net.exe'"), command),
                () -> assertTrue(command.contains("'powershell.exe'"), command),
                () -> assertTrue(command.contains("'cmd.exe'"), command),
                () -> assertTrue(command.contains("'rundll32.exe'"), command),
                // The windows that offer the same changes. Neither is a program, and an
                // executable rule could not have judged either of them.
                () -> assertTrue(command.contains("'firewall.cpl'"), command),
                () -> assertTrue(command.contains("'ncpa.cpl'"), command),
                () -> assertTrue(command.contains("'wf.msc'"), command),
                () -> assertTrue(command.contains("'services.msc'"), command),
                // A command line alone is not enough to reach a share or the network settings.
                () -> assertTrue(command.contains("Set-Service -Name LanmanServer -StartupType Disabled"),
                        command),
                () -> assertTrue(command.contains("SharingWizardOn"), command),
                () -> assertTrue(command.contains("NC_LanProperties"), command),
                () -> assertTrue(command.contains("SettingsPageVisibility"), command));
    }

    @Test
    void shouldPutEverythingBackWhenTheBlockIsReleased() {
        String command = ExecuteVmGuestCommandCommand.managementCommandsCommand(false);

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.contains("Remove-Item -Recurse -Force")),
                () -> assertTrue(command.contains("Set-Service -Name LanmanServer -StartupType Automatic")),
                () -> assertTrue(command.contains("Remove-ItemProperty")),
                () -> assertTrue(command.contains("NC_LanProperties")),
                () -> assertTrue(command.contains("NoInplaceSharing")),
                () -> assertTrue(command.contains("SettingsPageVisibility")),
                () -> assertTrue(command.contains("SharingWizardOn")),
                () -> assertFalse(command.contains("ItemData")));
    }

    @Test
    void turningTheCommandPromptBlockOffTakesOutItsRulesAndNobodyElsesv() {
        String command = ExecuteVmGuestCommandCommand.cmdCommand(false);

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.contains("-eq 'ovworks-cmd'"), command),
                () -> assertTrue(command.contains("Remove-Item -Recurse -Force"), command),
                // Another menu's rules, and any that were there first, are not this one's to drop.
                () -> assertFalse(command.contains("ovworks-management"), command),
                () -> assertFalse(command.contains("Remove-Item -Path '" //$NON-NLS-1$
                        + "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer"), command));
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
            ExecuteVmGuestCommandCommand.managementCommandsCommand(true),
            ExecuteVmGuestCommandCommand.managementCommandsCommand(false),
            ExecuteVmGuestCommandCommand.cmdCommand(true),
            ExecuteVmGuestCommandCommand.cmdCommand(false),
        }) {
            assertFalse(command.contains("Set-Service -Name AppIDSvc"), command); //$NON-NLS-1$
        }
        // Only the blocks touch it at all, and only to put an AppLocker policy out of the way.
        for (String command : new String[] {
            ExecuteVmGuestCommandCommand.managementCommandsCommand(true),
            ExecuteVmGuestCommandCommand.cmdCommand(true),
        }) {
            assertTrue(command.contains(
                    "Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet" //$NON-NLS-1$
                            + "\\Services\\AppIDSvc\" -Name Start"), command); //$NON-NLS-1$
        }
    }

    @Test
    void releasingAttemptsEveryStepRatherThanStoppingAtTheFirstFailure() {
        // The steps that release a block are what give the user back file sharing and the
        // network settings pages. Abandoning them halfway leaves the machine locked down by the
        // command that was asked to unlock it.
        String command = ExecuteVmGuestCommandCommand.managementCommandsCommand(false);

        assertTrue(command.startsWith("$failed = @(); "), command); //$NON-NLS-1$
        for (String step : new String[] {
            "rules", //$NON-NLS-1$
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
        String blocked = ExecuteVmGuestCommandCommand.managementCommandsCommand(true);
        String released = ExecuteVmGuestCommandCommand.managementCommandsCommand(false);

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
        String command = ExecuteVmGuestCommandCommand.managementCommandsCommand(true);

        assertFalse(command.contains("$failed"), command); //$NON-NLS-1$
    }

    /* The rules that replaced the AppLocker policies */

    private static final String SRP_RULES =
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Paths"; //$NON-NLS-1$

    @Test
    void blockingTheCommandPromptWritesOneRuleForItAndNothingElse() {
        String command = ExecuteVmGuestCommandCommand.cmdCommand(true);

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.contains("foreach ($name in @('cmd.exe'))"), command), //$NON-NLS-1$
                () -> assertTrue(command.contains("New-Item -Path $rule -Force"), command), //$NON-NLS-1$
                () -> assertTrue(command.contains(SRP_RULES), command),
                // The rule names the file and no folder, so a copy anywhere is refused as well.
                () -> assertFalse(command.contains("System32"), command)); //$NON-NLS-1$
    }

    @Test
    void theRulesAreWrittenTheWayWindowsWritesThem() {
        String command = ExecuteVmGuestCommandCommand.cmdCommand(true);

        org.junit.jupiter.api.Assertions.assertAll(
                // A rule may name a path holding environment variables; a plain string is literal.
                () -> assertTrue(command.contains(
                        "Set-ItemProperty -Path $rule -Name ItemData -Type ExpandString"), command), //$NON-NLS-1$
                () -> assertTrue(command.contains(
                        "Set-ItemProperty -Path $rule -Name SaferFlags -Type DWord -Value 0"), command), //$NON-NLS-1$
                // 0x40000: what has no rule of its own runs. The rules are the exceptions.
                () -> assertTrue(command.contains("-Name DefaultLevel -Value \"262144\""), command), //$NON-NLS-1$
                () -> assertTrue(command.contains("-Name TransparentEnabled -Value \"1\""), command)); //$NON-NLS-1$
    }

    @Test
    void theBlockLeavesAWayBackIn() {
        // PolicyScope 1 is everyone except the local administrators, which is the same choice the
        // AppLocker rules made by denying BUILTIN\Users and allowing SYSTEM. A policy that caught
        // the account the guest agent runs as could not be lifted from this dialog at all.
        for (String command : new String[] {
            ExecuteVmGuestCommandCommand.cmdCommand(true),
            ExecuteVmGuestCommandCommand.managementCommandsCommand(true),
        }) {
            assertTrue(command.contains("-Name PolicyScope -Value \"1\""), command); //$NON-NLS-1$
        }
    }

    @Test
    void appLockerIsTurnedOffBeforeTheRulesAreWritten() {
        // Where AppLocker is configured these rules are ignored, and a guest that has been through
        // an earlier version of this dialog is carrying an AppLocker policy.
        for (String command : new String[] {
            ExecuteVmGuestCommandCommand.cmdCommand(true),
            ExecuteVmGuestCommandCommand.managementCommandsCommand(true),
        }) {
            org.junit.jupiter.api.Assertions.assertAll(
                    () -> assertTrue(command.contains(ExecuteVmGuestCommandCommand.clearPolicy()), command),
                    () -> assertTrue(command.contains("Stop-Service AppIDSvc -Force"), command), //$NON-NLS-1$
                    () -> assertTrue(command.indexOf("Set-AppLockerPolicy") //$NON-NLS-1$
                            < command.indexOf("-Name DefaultLevel"), command)); //$NON-NLS-1$
        }
    }

    @Test
    void applyingTwiceDoesNotPileRulesUp() {
        String command = ExecuteVmGuestCommandCommand.cmdCommand(true);

        assertTrue(command.indexOf("Remove-Item -Recurse -Force") //$NON-NLS-1$
                < command.indexOf("foreach ($name in"), command); //$NON-NLS-1$
    }

    @Test
    void aBlockThatWroteNoRulesIsReportedAsAFailure() {
        // Writing a policy and enforcing one are different things, and the difference used to be
        // silent. The rules are read back and counted rather than assumed.
        String command = ExecuteVmGuestCommandCommand.managementCommandsCommand(true);
        int expected = ExecuteVmGuestCommandCommand.blockedNames().length;

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.contains("$written = @(Get-ChildItem"), command), //$NON-NLS-1$
                () -> assertTrue(command.contains("if ($written -ne " + expected + ") { throw"), command), //$NON-NLS-1$
                () -> assertTrue(command.contains(
                        "throw 'the rules are stored but not enforced'"), command)); //$NON-NLS-1$
    }

    @Test
    void eachMenuTakesOutOnlyItsOwnRules() {
        assertTrue(ExecuteVmGuestCommandCommand.cmdCommand(false)
                .contains("-eq 'ovworks-cmd'"), "cmd"); //$NON-NLS-1$ //$NON-NLS-2$
        assertTrue(ExecuteVmGuestCommandCommand.managementCommandsCommand(false)
                .contains("-eq 'ovworks-management'"), "management"); //$NON-NLS-1$ //$NON-NLS-2$
    }

    @Test
    void releasingStopsEnforcingOnlyWhenNothingElseIsDenied() {
        // Rules another menu wrote, or rules that were there before this dialog was ever used,
        // are not this one's to drop.
        String command = ExecuteVmGuestCommandCommand.cmdCommand(false);

        assertTrue(command.contains(").Count -eq 0) { " //$NON-NLS-1$
                + "Set-ItemProperty"), command); //$NON-NLS-1$
        assertTrue(command.contains("-Name TransparentEnabled -Value \"0\""), command); //$NON-NLS-1$
    }

    /* The network tab: a lease, or an address of its own */

    @Test
    void anAdapterOnALeaseAsksForOneAndWaitsToBeGivenIt() {
        String command = ExecuteVmGuestCommandCommand.networkCommand(
                true, true, MAC, null, null, null, null);

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.contains(
                        "Set-NetIPInterface -InterfaceAlias $name -Dhcp Enabled"), command), //$NON-NLS-1$
                // A lease cannot arrive while a manual address is sitting on the interface.
                () -> assertTrue(command.indexOf("Remove-NetIPAddress") //$NON-NLS-1$
                        < command.indexOf("-Dhcp Enabled"), command), //$NON-NLS-1$
                // The servers a lease carries are of no use behind a static list.
                () -> assertTrue(command.contains(
                        "Set-DnsClientServerAddress -InterfaceAlias $name -ResetServerAddresses"), command), //$NON-NLS-1$
                // The cmdlet returns before the server has answered, so the result is waited for.
                () -> assertTrue(command.contains("$_.PrefixOrigin -eq \"Dhcp\""), command), //$NON-NLS-1$
                () -> assertTrue(command.contains(
                        "throw \"$name asked for an address and was not given one\""), command)); //$NON-NLS-1$
    }

    @Test
    void anAdapterWithAnAddressOfItsOwnStopsAskingForALease() {
        String command = ExecuteVmGuestCommandCommand.networkCommand(
                true, false, MAC, "192.168.1.50", "255.255.255.0", "192.168.1.1", "8.8.8.8");

        org.junit.jupiter.api.Assertions.assertAll(
                () -> assertTrue(command.contains(
                        "Set-NetIPInterface -InterfaceAlias $name -Dhcp Disabled"), command), //$NON-NLS-1$
                () -> assertTrue(command.contains("New-NetIPAddress -InterfaceAlias $name " //$NON-NLS-1$
                        + "-IPAddress 192.168.1.50 -PrefixLength 24 -DefaultGateway 192.168.1.1"), command), //$NON-NLS-1$
                () -> assertTrue(command.contains("Set-DnsClientServerAddress -InterfaceAlias $name " //$NON-NLS-1$
                        + "-ServerAddresses \"8.8.8.8\""), command)); //$NON-NLS-1$
    }

    @Test
    void severalNameServersMayBeGivenAndOnlyAddressesAreKept() {
        String command = ExecuteVmGuestCommandCommand.networkCommand(
                true, false, MAC, "192.168.1.50", "255.255.255.0", "192.168.1.1",
                "8.8.8.8, 1.1.1.1 not-an-address");

        assertTrue(command.contains("-ServerAddresses \"8.8.8.8\",\"1.1.1.1\""), command); //$NON-NLS-1$
    }

    @Test
    void anEmptyNameServerFieldLeavesWhateverTheGuestHad() {
        // Clearing the servers on an interface that was given none would take away what it
        // already had, which is not what leaving a field blank asks for.
        String command = ExecuteVmGuestCommandCommand.networkCommand(
                true, false, MAC, "192.168.1.50", "255.255.255.0", "192.168.1.1", "   ");

        assertFalse(command.contains("Set-DnsClientServerAddress"), command); //$NON-NLS-1$
    }
}
