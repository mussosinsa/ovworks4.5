package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class AuditLogCapacityMonitorTest {

    @Test
    void warnsWhenFivePercentOrLessRemains() {
        assertFalse(AuditLogCapacityMonitor.isWithinWarningRange(94, 100, 5));
        assertTrue(AuditLogCapacityMonitor.isWithinWarningRange(95, 100, 5));
        assertTrue(AuditLogCapacityMonitor.isWithinWarningRange(99, 100, 5));
    }

    @Test
    void exceededCapacityIsNotReportedAsWarning() {
        assertFalse(AuditLogCapacityMonitor.isWithinWarningRange(100, 100, 5));
        assertFalse(AuditLogCapacityMonitor.isWithinWarningRange(101, 100, 5));
    }
}
