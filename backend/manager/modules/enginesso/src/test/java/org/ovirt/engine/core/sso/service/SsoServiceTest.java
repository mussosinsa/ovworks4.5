package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.sso.api.ClientSerialRejectedException;
import org.ovirt.engine.core.sso.api.OAuthException;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck.Refusal;

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

    @Test
    void saysWhyASerialWasRefusedSoTheEventCanSayIt() {
        assertEquals(Refusal.MISSING, assertThrows(ClientSerialRejectedException.class,
                () -> SsoService.validateClientSerial(null, "client-serial")).getRefusal());
        assertEquals(Refusal.INVALID, assertThrows(ClientSerialRejectedException.class,
                () -> SsoService.validateClientSerial("incorrect", "client-serial")).getRefusal());
        // A serial that cannot be read lets nothing in rather than everything.
        assertEquals(Refusal.UNVERIFIABLE, assertThrows(ClientSerialRejectedException.class,
                () -> SsoService.validateClientSerial("client-serial", null)).getRefusal());
    }
}
