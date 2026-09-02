package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.sso.api.OAuthException;

class SsoServiceTest {

    @Test
    void acceptsMatchingClientSerialWithoutApplyingSourceAddressRestrictions() {
        assertDoesNotThrow(() -> SsoService.validateClientSerial("client-serial", "client-serial"));
    }

    @Test
    void rejectsMissingOrIncorrectClientSerial() {
        assertThrows(OAuthException.class, () -> SsoService.validateClientSerial(null, "client-serial"));
        assertThrows(OAuthException.class, () -> SsoService.validateClientSerial("incorrect", "client-serial"));
    }
}
