package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.uutils.security.LoginInputPolicy;
import org.ovirt.engine.core.uutils.security.LoginInputPolicy.Refusal;

class LoginInputAuditTest {

    @Test
    void aRefusedIdIsNotRecorded() {
        Refusal refusal = LoginInputPolicy.checkUserName("admin'--").get();
        assertEquals("N/A", LoginInputAudit.recordedUserName("admin'--", refusal));
    }

    @Test
    void theIdOfARefusedPasswordIsRecordedButNeverThePassword() {
        Refusal refusal = LoginInputPolicy.checkPassword("Secret'or1=1").get();
        assertEquals("admin", LoginInputAudit.recordedUserName("admin", refusal));
        assertEquals(
                "LOGIN_INPUT_REJECTED user=admin sourceIp=192.168.20.31 channel=LOGIN_PAGE"
                        + " field=PASSWORD reason=SQL_INJECTION",
                LoginInputAudit.describe("admin", "192.168.20.31", LoginReplayAudit.Channel.LOGIN_PAGE, refusal));
    }

    @Test
    void theEngineAcceptsTheEventByThisName() {
        assertEquals("USER_VDC_LOGIN_INPUT_REJECTED", LoginInputAudit.AUDIT_LOG_TYPE);
    }
}
