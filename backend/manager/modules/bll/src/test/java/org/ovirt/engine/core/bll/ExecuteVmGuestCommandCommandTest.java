package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ExecuteVmGuestCommandCommandTest {

    private static final String LOOKUP = "$mac = \"001A4A160151\"; "
            + "$adapter = Get-NetAdapter | Where-Object "
            + "{ ($_.MacAddress -replace \"[^0-9A-Fa-f]\", \"\") -eq $mac } | Select-Object -First 1; "
            + "if (-not $adapter) { throw \"No network adapter with MAC address $mac was found\" }; "
            + "$name = $adapter.Name; ";

    @Test
    void shouldDisableTheAdapterThatCarriesTheGivenMacAddress() {
        assertEquals(
                LOOKUP + "Disable-NetAdapter -Name $name -Confirm:$false",
                ExecuteVmGuestCommandCommand.networkCommand(
                        false, "00:1a:4a:16:01:51", null, null, null));
    }

    @Test
    void shouldEnableAdapterAndConfigureStaticIp() {
        assertEquals(
                LOOKUP + "Enable-NetAdapter -Name $name -Confirm:$false; "
                        + "Remove-NetIPAddress -InterfaceAlias $name -Confirm:$false "
                        + "-ErrorAction SilentlyContinue; New-NetIPAddress -InterfaceAlias $name "
                        + "-IPAddress 192.168.1.100 -PrefixLength 24 -DefaultGateway 192.168.1.1",
                ExecuteVmGuestCommandCommand.networkCommand(
                        true, "00:1a:4a:16:01:51", "192.168.1.100", "255.255.255.0", "192.168.1.1"));
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
    void shouldEscapeSingleQuotesWhenQuotingForTheShell() {
        assertEquals("'win'\"'\"'01'", ExecuteVmGuestCommandCommand.shellQuote("win'01"));
    }
}
