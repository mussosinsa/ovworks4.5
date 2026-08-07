package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;

public class AdminLoginLockoutServiceTest {

    @Test
    void shouldLockAfterFiveFailures() {
        AdminLoginLockoutService service = new AdminLoginLockoutService();
        Instant now = Instant.now();
        String principal = "admin@internal";

        for (int i = 1; i <= 4; i++) {
            AdminLoginLockoutService.FailureResult result = service.recordFailure(principal, now, 5, Duration.ofHours(24));
            assertFalse(result.isLocked());
        }

        AdminLoginLockoutService.FailureResult result = service.recordFailure(principal, now, 5, Duration.ofHours(24));
        assertTrue(result.isLocked());
        assertNotNull(result.getLockedUntil());
        assertTrue(service.isLocked(principal, now));
    }

    @Test
    void shouldAutoUnlockAfterLockDuration() {
        AdminLoginLockoutService service = new AdminLoginLockoutService();
        Instant now = Instant.now();
        String principal = "admin@internal";

        service.recordFailure(principal, now, 1, Duration.ofHours(24));
        assertTrue(service.isLocked(principal, now.plusSeconds(1)));

        Instant after24h = now.plus(Duration.ofHours(24)).plusSeconds(1);
        assertFalse(service.isLocked(principal, after24h));
    }

    @Test
    void shouldResetOnSuccess() {
        AdminLoginLockoutService service = new AdminLoginLockoutService();
        Instant now = Instant.now();
        String principal = "admin@internal";

        service.recordFailure(principal, now, 5, Duration.ofHours(24));
        service.recordSuccess(principal);

        AdminLoginLockoutService.FailureResult result = service.recordFailure(principal, now, 5, Duration.ofHours(24));
        assertFalse(result.isLocked());
        assertEquals(1, result.getFailureCount());
    }
}
