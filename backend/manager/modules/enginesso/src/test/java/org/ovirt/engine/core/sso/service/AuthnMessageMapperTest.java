package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.api.extensions.ExtMap;
import org.ovirt.engine.api.extensions.aaa.Authn;
import org.ovirt.engine.core.sso.api.SsoConstants;

public class AuthnMessageMapperTest {

    @Test
    public void mapsMissingAuthenticationResultToGeneralFailure() {
        assertEquals(
                SsoConstants.APP_ERROR_USER_FAILED_TO_AUTHENTICATE,
                AuthnMessageMapper.mapErrorCode(null, null, "internal", new ExtMap()));
    }

    @Test
    public void mapsInvalidCredentialsToAuthenticationFailure() {
        ExtMap output = new ExtMap().mput(Authn.InvokeKeys.RESULT, Authn.AuthResult.CREDENTIALS_INVALID);

        assertEquals(
                SsoConstants.APP_ERROR_USER_FAILED_TO_AUTHENTICATE,
                AuthnMessageMapper.mapErrorCode(null, null, "internal", output));
    }
}
