package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atMost;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.lang.reflect.Field;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.bll.GuestCriticalEventAuditManager.GuestEvent;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.action.ExecuteVmGuestCommandParameters;
import org.ovirt.engine.core.common.businessentities.VM;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;

public class GuestCriticalEventAuditManagerTest {

    private AuditLogDirector auditLogDirector;

    /**
     * @return a manager with nothing but somewhere to write, which is all these exercise
     *
     * <p>Through the field rather than through a constructor: the class is built by the container
     * and has no constructor of its own to hand one to.</p>
     */
    private GuestCriticalEventAuditManager managerWithMockedAudit() {
        auditLogDirector = mock(AuditLogDirector.class);
        GuestCriticalEventAuditManager manager = new GuestCriticalEventAuditManager();
        try {
            Field field = GuestCriticalEventAuditManager.class.getDeclaredField("auditLogDirector");
            field.setAccessible(true);
            field.set(manager, auditLogDirector);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
        return manager;
    }

    private static final String LINE = "4821\tSystem\tError\tdisk\t7\t2026-09-19 16:15:17\t"
            + "The device, \\Device\\Harddisk0\\DR0, has a bad block.";

    @Test
    public void aLineSaysWhichEventItIs() {
        GuestEvent event = GuestEvent.parse(LINE);

        assertNotNull(event);
        assertAll(
                () -> assertEquals(4821L, event.recordId),
                () -> assertEquals("System", event.log),
                () -> assertEquals("Error", event.level),
                () -> assertEquals("disk", event.source),
                () -> assertEquals("7", event.eventId),
                () -> assertEquals("2026-09-19 16:15:17", event.time),
                () -> assertTrue(event.message.startsWith("The device")));
    }

    @Test
    public void aMessageMayHoldAnythingButATab() {
        // The line is split into a fixed number of fields, so a message with a tab in it stays
        // whole instead of being read as fields that are not there.
        GuestEvent event = GuestEvent.parse("9\tApplication\tCritical\tsvc\t1\t2026-09-19 10:00:00\ta\tb");

        assertNotNull(event);
        assertEquals("a\tb", event.message);
    }

    @Test
    public void aLineThatDoesNotSayIsSkippedRatherThanThrowing() {
        // Whatever a guest's PowerShell wrote. One odd line is not a reason to drop the rest.
        assertAll(
                () -> assertNull(GuestEvent.parse("")),
                () -> assertNull(GuestEvent.parse("   ")),
                () -> assertNull(GuestEvent.parse("not\tenough\tfields")),
                () -> assertNull(GuestEvent.parse(
                        "notanumber\tSystem\tError\tdisk\t7\t2026-09-19 16:15:17\tx")));
    }

    @Test
    public void theQueryAsksForWhatIsWrongAndNotForEverything() {
        String command = ExecuteVmGuestCommandCommand.criticalGuestEventsCommand(2);

        assertAll(
                // 1 is Critical and 2 is Error. Everything else is what the guest does all day.
                () -> assertTrue(command.contains("Level = @(1, 2)"), command),
                () -> assertTrue(command.contains("LogName = @(\"System\", \"Application\")"), command),
                // The Security log is a subject of its own and the whole of it is noise here.
                () -> assertTrue(!command.contains("Security"), command),
                () -> assertTrue(command.contains("AddHours(-2)"), command),
                // The record number is what lets the same event be recognised across passes.
                () -> assertTrue(command.contains("$_.RecordId"), command),
                () -> assertTrue(command.contains("Sort-Object RecordId"), command),
                () -> assertTrue(command.contains(
                        "-MaxEvents " + ExecuteVmGuestCommandCommand.CRITICAL_EVENT_LIMIT), command));
    }

    @Test
    public void theQueryIsOneLinePerEventWithTabsBetween() {
        String command = ExecuteVmGuestCommandCommand.criticalGuestEventsCommand(6);

        assertTrue(command.contains("\"{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}\""), command);
        assertEquals(GuestEventFields.COUNT, 7, "the parser reads seven of them");
    }

    /** Kept next to the format so the two are changed together. */
    private static final class GuestEventFields {
        private static final int COUNT = 7;
    }

    /* Recorded once, and the estate reached in turn */

    private static String line(long recordId, String log) {
        return recordId + "\t" + log + "\tError\tdisk\t7\t2026-09-19 16:15:17\tbad block";
    }

    private static VM vm(String id) {
        VM vm = new VM();
        vm.setId(new Guid(id));
        vm.setName("vm-" + id.charAt(0));
        return vm;
    }

    @Test
    public void anEventIsRecordedOnceHoweverOftenItIsSeen() {
        // A pass looks back hours and the passes are minutes apart, so the same event comes back
        // again and again. The guest numbers them, and the numbers only go up.
        GuestCriticalEventAuditManager manager = managerWithMockedAudit();
        VM vm = vm("11111111-1111-1111-1111-111111111111");

        manager.record(vm, line(10, "System") + "\n" + line(11, "System"));
        manager.record(vm, line(10, "System") + "\n" + line(11, "System") + "\n" + line(12, "System"));

        verify(auditLogDirector, times(3))
                .log(any(AuditLogable.class), eq(AuditLogType.VM_GUEST_CRITICAL_EVENT));
    }

    @Test
    public void eachLogIsCountedOnItsOwn() {
        // The numbers are per log, so one log being further along says nothing about the other.
        GuestCriticalEventAuditManager manager = managerWithMockedAudit();
        VM vm = vm("22222222-2222-2222-2222-222222222222");

        manager.record(vm, line(500, "System"));
        manager.record(vm, line(3, "Application"));

        verify(auditLogDirector, times(2))
                .log(any(AuditLogable.class), eq(AuditLogType.VM_GUEST_CRITICAL_EVENT));
    }

    @Test
    public void aClearedLogStartsAgainRatherThanGoingSilent() {
        // Clearing the log restarts the numbering. Read as old events, everything the guest
        // recorded afterwards would be skipped for as long as it took to climb back.
        GuestCriticalEventAuditManager manager = managerWithMockedAudit();
        VM vm = vm("33333333-3333-3333-3333-333333333333");

        manager.record(vm, line(9000, "System"));
        manager.record(vm, line(2, "System"));

        verify(auditLogDirector, times(2))
                .log(any(AuditLogable.class), eq(AuditLogType.VM_GUEST_CRITICAL_EVENT));
    }

    @Test
    public void oneVmInALoopCannotFillTheEventList() {
        GuestCriticalEventAuditManager manager = managerWithMockedAudit();
        VM vm = vm("44444444-4444-4444-4444-444444444444");
        StringBuilder burst = new StringBuilder();
        for (int i = 1; i <= 100; i++) {
            burst.append(line(i, "System")).append("\n");
        }

        manager.record(vm, burst.toString());

        verify(auditLogDirector, atMost(50))
                .log(any(AuditLogable.class), eq(AuditLogType.VM_GUEST_CRITICAL_EVENT));
    }

    /* The request itself */

    @Test
    public void theRequestIsOneThisCommandWillAccept() {
        // Left out of what validate() knows about, a request for these falls through to the check
        // that wants a .bat file to run - which this never names - and is refused every time.
        ExecuteVmGuestCommandParameters parameters = new ExecuteVmGuestCommandParameters();
        parameters.setCriticalEventsRequested(true);
        parameters.setLookbackHours(2);

        assertAll(
                () -> assertEquals(Boolean.TRUE, parameters.getCriticalEventsRequested()),
                () -> assertEquals(2, parameters.getLookbackHours()),
                // and it is not any of the others, which is what the one-operation check counts
                () -> assertNull(parameters.getGuestEventsRequested()),
                () -> assertNull(parameters.getCmdBlocked()),
                () -> assertNull(parameters.getManagementCommandsBlocked()),
                () -> assertNull(parameters.getNetworkEnabled()));
    }
}
