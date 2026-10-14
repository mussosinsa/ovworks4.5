package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.aaa.CreateUserSessionsError;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;

class CreateUserSessionCommandTest {

    // --- dedicated login IP enforcement ---

    @Test
    void aMatchingDedicatedIpIsAllowed() {
        assertFalse(CreateUserSessionCommand.isLoginDenied(true, false, "10.0.0.5", "10.0.0.5"));
        assertFalse(CreateUserSessionCommand.isLoginDenied(true, true, "10.0.0.5", " 10.0.0.5 "));
    }

    @Test
    void aMismatchedDedicatedIpIsDenied() {
        assertTrue(CreateUserSessionCommand.isLoginDenied(true, false, "10.0.0.5", "10.0.0.6"));
        // A registered address is enforced even for a super user.
        assertTrue(CreateUserSessionCommand.isLoginDenied(true, true, "10.0.0.5", "10.0.0.6"));
    }

    @Test
    void aNonAdminInternalUserWithoutADedicatedIpIsDenied() {
        assertTrue(CreateUserSessionCommand.isLoginDenied(true, false, null, "10.0.0.5"));
        assertTrue(CreateUserSessionCommand.isLoginDenied(true, false, "   ", "10.0.0.5"));
    }

    @Test
    void aSuperUserWithoutADedicatedIpIsAllowedSoAdminsAreNotLockedOut() {
        assertFalse(CreateUserSessionCommand.isLoginDenied(true, true, null, "10.0.0.5"));
    }

    @Test
    void anExternalUserIsNeverRestricted() {
        assertFalse(CreateUserSessionCommand.isLoginDenied(false, false, null, "10.0.0.5"));
        assertFalse(CreateUserSessionCommand.isLoginDenied(false, false, "10.0.0.5", "10.0.0.6"));
    }

    @Test
    void aLoginRefusedForItsAddressEndsWithTheDedicatedIpEvent() {
        assertEquals(AuditLogType.USER_LOGIN_IP_DENIED,
                CreateUserSessionCommand.auditLogTypeFor(false, CreateUserSessionsError.LOGIN_IP_NOT_ALLOWED));
        assertEquals(AuditLogType.USER_VDC_LOGIN, CreateUserSessionCommand.auditLogTypeFor(true, null));
        assertEquals(AuditLogType.USER_VDC_LOGIN_FAILED,
                CreateUserSessionCommand.auditLogTypeFor(false, CreateUserSessionsError.USER_NOT_AUTHORIZED));
    }

    @Test
    void theEventSaysWhetherTheAddressDifferedOrWasNeverRegistered() {
        assertEquals(CreateUserSessionCommand.REASON_DEDICATED_IP_MISMATCH,
                CreateUserSessionCommand.deniedReason("10.0.0.5"));
        assertEquals(CreateUserSessionCommand.REASON_DEDICATED_IP_NOT_REGISTERED,
                CreateUserSessionCommand.deniedReason(null));
        assertEquals(CreateUserSessionCommand.REASON_DEDICATED_IP_NOT_REGISTERED,
                CreateUserSessionCommand.deniedReason("  "));
    }

    @Test
    void everyRefusedAttemptIsRecorded() {
        assertEquals(0, AuditLogType.USER_LOGIN_IP_DENIED.getEventFloodRate());
    }

    @Test
    void onlyASuperUserWithoutAnAddressIsLetInByTheSafeguard() {
        assertTrue(CreateUserSessionCommand.isUnregisteredSuperUserLogin(true, true, null));
        assertFalse(CreateUserSessionCommand.isUnregisteredSuperUserLogin(true, true, "10.0.0.5"));
        assertFalse(CreateUserSessionCommand.isUnregisteredSuperUserLogin(true, false, null));
        assertFalse(CreateUserSessionCommand.isUnregisteredSuperUserLogin(false, true, null));
    }

    @Test
    void theDedicatedIpIsReadBackFromItsJsonStringForm() {
        // Stored as a JSON string in the jsonb property column.
        assertEquals("192.168.0.5", CreateUserSessionCommand.dedicatedIpFromContent("\"192.168.0.5\""));
        assertEquals("fe80::1", CreateUserSessionCommand.dedicatedIpFromContent("\"fe80::1\""));
    }

    @Test
    void emptyDedicatedIpContentReadsAsNull() {
        assertNull(CreateUserSessionCommand.dedicatedIpFromContent(null));
        assertNull(CreateUserSessionCommand.dedicatedIpFromContent(""));
    }

    @Test
    void userSessionLimitOverridesEngineDefault() {
        assertEquals(3, CreateUserSessionCommand.resolveSessionLimit(sessionLimit("3"), 1)); //$NON-NLS-1$
    }

    @Test
    void missingOrInvalidUserSessionLimitUsesEngineDefault() {
        assertEquals(2, CreateUserSessionCommand.resolveSessionLimit(null, 2));
        assertEquals(2, CreateUserSessionCommand.resolveSessionLimit(sessionLimit("invalid"), 2)); //$NON-NLS-1$
        assertEquals(2, CreateUserSessionCommand.resolveSessionLimit(sessionLimit("0"), 2)); //$NON-NLS-1$
    }

    private UserProfileProperty sessionLimit(String content) {
        return UserProfileProperty.builder()
                .withName("CONCURRENT_SESSION_LIMIT") //$NON-NLS-1$
                .withTypeJson()
                .withContent(content)
                .build();
    }
}
