package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class ExecuteVmGuestCommandCommandTest {

    @Test
    void shouldDisableKoreanEthernetAdapter() {
        assertEquals(
                "Disable-NetAdapter -Name \"\uc774\ub354\ub137\" -Confirm:$false",
                ExecuteVmGuestCommandCommand.networkCommand(false, null, null, null));
    }

    @Test
    void shouldEnableAdapterAndConfigureStaticIp() {
        assertEquals(
                "Enable-NetAdapter -Name \"\uc774\ub354\ub137\" -Confirm:$false; "
                        + "Remove-NetIPAddress -InterfaceAlias \"\uc774\ub354\ub137\" -Confirm:$false "
                        + "-ErrorAction SilentlyContinue; New-NetIPAddress -InterfaceAlias \"\uc774\ub354\ub137\" "
                        + "-IPAddress 192.168.1.100 -PrefixLength 24 -DefaultGateway 192.168.1.1",
                ExecuteVmGuestCommandCommand.networkCommand(
                        true, "192.168.1.100", "255.255.255.0", "192.168.1.1"));
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
}
