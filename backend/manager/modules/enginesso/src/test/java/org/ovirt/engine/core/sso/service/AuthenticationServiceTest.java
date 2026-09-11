package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.sso.api.SsoConstants;

class AuthenticationServiceTest {

    @Test
    void expiredPasswordIsNotRecordedAsAnAuthenticationFailure() {
        assertFalse(AuthenticationService.shouldRecordAuthenticationFailure(
                SsoConstants.APP_ERROR_USER_PASSWORD_EXPIRED_CHANGE_URL_PROVIDED));
    }

    @Test
    void invalidCredentialsAreRecordedAsAnAuthenticationFailure() {
        assertTrue(AuthenticationService.shouldRecordAuthenticationFailure(
                SsoConstants.APP_ERROR_INVALID_CREDENTIALS));
    }

    @Test
    void protectedAdministratorIsBlockedFromNonInteractiveLogin() {
        assertTrue(AuthenticationService.shouldBlockNonInteractiveAdmin(false, true));
    }

    @Test
    void protectedAdministratorCanUseInteractiveWebAdminLogin() {
        assertFalse(AuthenticationService.shouldBlockNonInteractiveAdmin(true, true));
    }

    @Test
    void otherAccountsCanUseNonInteractiveLogin() {
        assertFalse(AuthenticationService.shouldBlockNonInteractiveAdmin(false, false));
    }

    @Test
    void lockThresholdUsesDedicatedAuditEvent() {
        assertEquals("USER_ACCOUNT_LOCKED_BY_LOGIN_FAILURES",
                AuthenticationService.getLockoutAuditLogType(
                        true, "USER_ACCOUNT_LOCKED user=admin@internal failCount=5"));
    }

    @Test
    void ordinaryLoginFailureKeepsExistingAuditEvent() {
        assertNull(AuthenticationService.getLockoutAuditLogType(
                true, "USER_LOGIN_FAILED user=admin@internal failCount=1"));
    }
}
