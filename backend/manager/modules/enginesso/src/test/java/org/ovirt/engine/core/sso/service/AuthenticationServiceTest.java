package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.sso.api.Credentials;
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
    void aRefusedPasswordIsRecordedAsAnAuthenticationFailure() {
        assertTrue(AuthenticationService.shouldRecordAuthenticationFailure(
                SsoConstants.APP_ERROR_USER_FAILED_TO_AUTHENTICATE));
    }

    @Test
    void anExpiredPasswordWithoutAChangeUrlIsNotRecordedEither() {
        assertFalse(AuthenticationService.shouldRecordAuthenticationFailure(
                SsoConstants.APP_ERROR_USER_PASSWORD_EXPIRED));
    }

    @Test
    void anAccountTheProviderLockedOrDisabledIsNotAPasswordFailure() {
        assertFalse(AuthenticationService.shouldRecordAuthenticationFailure(
                SsoConstants.APP_ERROR_USER_ACCOUNT_DISABLED));
    }

    @Test
    void anExpiredAccountIsNotAPasswordFailure() {
        assertFalse(AuthenticationService.shouldRecordAuthenticationFailure(
                SsoConstants.APP_ERROR_USER_ACCOUNT_EXPIRED));
    }

    @Test
    void aProviderThatTimedOutGaveNoVerdictToCount() {
        assertFalse(AuthenticationService.shouldRecordAuthenticationFailure(
                SsoConstants.APP_ERROR_USER_FAILED_TO_AUTHENTICATE_TIMED_OUT));
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
                        "USER_ACCOUNT_LOCKED user=admin@internal failCount=5"));
    }

    @Test
    void lockThresholdUsesDedicatedAuditEventForOrdinaryAccountsToo() {
        assertEquals("USER_ACCOUNT_LOCKED_BY_LOGIN_FAILURES",
                AuthenticationService.getLockoutAuditLogType(
                        "USER_ACCOUNT_LOCKED user=user01@internal failCount=5"));
    }

    @Test
    void ordinaryLoginFailureKeepsExistingAuditEvent() {
        assertNull(AuthenticationService.getLockoutAuditLogType(
                "USER_LOGIN_FAILED user=admin@internal failCount=1"));
    }

    @Test
    void lockedAdministratorIsToldTheAccountIsLocked() {
        assertEquals(SsoConstants.APP_ERROR_USER_ACCOUNT_DISABLED,
                AuthenticationService.lockedAccountErrorCode(true));
    }

    @Test
    void everyOtherLockedAccountIsToldWhatAMistypedPasswordIsTold() {
        assertEquals(SsoConstants.APP_ERROR_USER_FAILED_TO_AUTHENTICATE,
                AuthenticationService.lockedAccountErrorCode(false));
    }

    @Test
    void failuresAreCountedUnderTheNameAndTheProfile() {
        assertEquals("user01@internal", AuthenticationService.principalKey(
                new Credentials("User01", "password", "Internal", true)));
    }
}
