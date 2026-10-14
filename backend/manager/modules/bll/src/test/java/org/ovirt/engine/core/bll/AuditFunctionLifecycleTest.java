package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;

class AuditFunctionLifecycleTest {

    private final List<AuditLogType> recorded = new ArrayList<>();
    private final List<AuditLogable> events = new ArrayList<>();

    private final AuditFunctionLifecycle lifecycle = new AuditFunctionLifecycle() {
        @Override
        protected void record(AuditLogable event, AuditLogType type) {
            events.add(event);
            recorded.add(type);
        }
    };

    @Test
    void theServiceStartingAndStoppingIsRecordedAsTheAuditFunctionStartingAndEnding() {
        lifecycle.started("4.5.7");
        assertTrue(lifecycle.isRunning());
        lifecycle.stopped("4.5.7", AuditFunctionLifecycle.REASON_STOPPED);
        assertFalse(lifecycle.isRunning());
        assertEquals(List.of(AuditLogType.AUDIT_FUNCTION_STARTED, AuditLogType.AUDIT_FUNCTION_STOPPED), recorded);
        assertEquals(AuditFunctionLifecycle.REASON_STARTED, events.get(0).getCustomValues().get("reason"));
        assertEquals(AuditFunctionLifecycle.REASON_STOPPED, events.get(1).getCustomValues().get("reason"));
        assertEquals("4.5.7", events.get(1).getCustomValues().get("engineversion"));
    }

    @Test
    void eachIsRecordedOncePerRun() {
        // The engine's initialization can be entered more than once; the shutdown follows a stop
        // already recorded for a failed initialization.
        lifecycle.started("4.5.7");
        lifecycle.started("4.5.7");
        lifecycle.stopped("4.5.7", AuditFunctionLifecycle.REASON_INITIALIZATION_FAILED);
        lifecycle.stopped("4.5.7", AuditFunctionLifecycle.REASON_STOPPED);
        assertEquals(List.of(AuditLogType.AUDIT_FUNCTION_STARTED, AuditLogType.AUDIT_FUNCTION_STOPPED), recorded);
        assertEquals(AuditFunctionLifecycle.REASON_INITIALIZATION_FAILED, events.get(1).getCustomValues().get("reason"));
    }

    @Test
    void noEndIsRecordedWithoutAStart() {
        lifecycle.stopped("4.5.7", AuditFunctionLifecycle.REASON_STOPPED);
        assertTrue(recorded.isEmpty());
    }

    @Test
    void anUnknownVersionStillGivesAReadableRecord() {
        assertEquals("UNKNOWN", AuditFunctionLifecycle.event(null, AuditFunctionLifecycle.REASON_STARTED)
                .getCustomValues().get("engineversion"));
    }

    @Test
    void aRecordThatCannotBeWrittenDoesNotStopTheEngine() {
        AuditFunctionLifecycle failing = new AuditFunctionLifecycle() {
            @Override
            protected void record(AuditLogable event, AuditLogType type) {
                throw new IllegalStateException("database unreachable");
            }
        };
        failing.started("4.5.7");
        failing.stopped("4.5.7", AuditFunctionLifecycle.REASON_STOPPED);
        assertFalse(failing.isRunning());
    }
}
