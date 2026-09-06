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
                () -> org.junit.jupiter.api.Assertions.assertTrue(command.contains("Set-Service -Name AppIDSvc")),
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
                () -> org.junit.jupiter.api.Assertions.assertTrue(command.contains("StartupType Manual")));
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
}
