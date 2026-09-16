package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.sso.api.LoginFailureRecord;

public class AdminLoginLockoutServiceTest {

    @Test
    void shouldLockAfterFiveFailures() {
        AdminLoginLockoutService service = new AdminLoginLockoutService();
        Instant now = Instant.now();
        String principal = "admin@internal";

        for (int i = 1; i <= 4; i++) {
            LoginFailureRecord result = service.recordFailure(principal, now, 5, Duration.ofHours(24));
            assertFalse(result.isLocked());
        }

        LoginFailureRecord result = service.recordFailure(principal, now, 5, Duration.ofHours(24));
        assertTrue(result.isLocked());
        assertNotNull(result.getLockedUntil());
        assertTrue(service.getLockedUntil(principal).isAfter(now));
    }

    @Test
    void shouldAutoUnlockAfterLockDuration() {
        AdminLoginLockoutService service = new AdminLoginLockoutService();
        Instant now = Instant.now();
        String principal = "admin@internal";

        service.recordFailure(principal, now, 1, Duration.ofHours(24));
        assertTrue(service.getLockedUntil(principal).isAfter(now.plusSeconds(1)));

        Instant after24h = now.plus(Duration.ofHours(24)).plusSeconds(1);
        assertFalse(service.getLockedUntil(principal).isAfter(after24h));
    }

    @Test
    void shouldNotExtendALockItIsStillUnder() {
        AdminLoginLockoutService service = new AdminLoginLockoutService();
        Instant now = Instant.now();
        String principal = "admin@internal";

        Instant lockedUntil = service.recordFailure(principal, now, 1, Duration.ofMinutes(5)).getLockedUntil();
        LoginFailureRecord duringLock =
                service.recordFailure(principal, now.plusSeconds(60), 1, Duration.ofMinutes(5));

        assertEquals(lockedUntil, duringLock.getLockedUntil());
    }

    @Test
    void shouldStartAFreshCountOnceTheLockHasRunOut() {
        AdminLoginLockoutService service = new AdminLoginLockoutService();
        Instant now = Instant.now();
        String principal = "admin@internal";

        service.recordFailure(principal, now, 2, Duration.ofMinutes(5));
        service.recordFailure(principal, now, 2, Duration.ofMinutes(5));

        LoginFailureRecord afterLock =
                service.recordFailure(principal, now.plus(Duration.ofMinutes(6)), 2, Duration.ofMinutes(5));
        assertEquals(1, afterLock.getFailureCount());
        assertFalse(afterLock.isLocked());
    }

    @Test
    void shouldReleaseALockOnlyOnceItHasRunOut() {
        AdminLoginLockoutService service = new AdminLoginLockoutService();
        Instant now = Instant.now();
        String principal = "admin@internal";

        service.recordFailure(principal, now, 1, Duration.ofMinutes(5));
        assertFalse(service.releaseIfExpired(principal, now.plusSeconds(60)));
        assertNotNull(service.getLockedUntil(principal));

        assertTrue(service.releaseIfExpired(principal, now.plus(Duration.ofMinutes(6))));
        assertNull(service.getLockedUntil(principal));
    }

    @Test
    void shouldTellOnlyTheFirstCallerThatItReleasedTheLock() {
        AdminLoginLockoutService service = new AdminLoginLockoutService();
        Instant now = Instant.now();
        String principal = "admin@internal";
        Instant afterTheLock = now.plus(Duration.ofMinutes(6));

        service.recordFailure(principal, now, 1, Duration.ofMinutes(5));

        assertTrue(service.releaseIfExpired(principal, afterTheLock));
        assertFalse(service.releaseIfExpired(principal, afterTheLock));
    }

    @Test
    void shouldReportNothingToReleaseForAnAccountThatWasNeverLocked() {
        AdminLoginLockoutService service = new AdminLoginLockoutService();

        assertFalse(service.releaseIfExpired("admin@internal", Instant.now()));
    }

    @Test
    void shouldResetOnSuccess() {
        AdminLoginLockoutService service = new AdminLoginLockoutService();
        Instant now = Instant.now();
        String principal = "admin@internal";

        service.recordFailure(principal, now, 5, Duration.ofHours(24));
        service.recordSuccess(principal);
        assertNull(service.getLockedUntil(principal));

        LoginFailureRecord result = service.recordFailure(principal, now, 5, Duration.ofHours(24));
        assertFalse(result.isLocked());
        assertEquals(1, result.getFailureCount());
    }
}
