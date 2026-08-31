package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
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
}
