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
}
