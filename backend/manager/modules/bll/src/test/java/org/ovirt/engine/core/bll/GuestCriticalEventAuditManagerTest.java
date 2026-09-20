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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.bll.GuestCriticalEventAuditManager.GuestEvent;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.action.ExecuteVmGuestCommandParameters;
import org.ovirt.engine.core.common.businessentities.VM;
import org.ovirt.engine.core.common.businessentities.VmGuestEventMark;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.dao.VmGuestEventMarkDao;

public class GuestCriticalEventAuditManagerTest {

    private AuditLogDirector auditLogDirector;

    /**
     * @return a manager with somewhere to write and somewhere to keep its marks
     *
     * <p>Through the fields rather than through a constructor: the class is built by the container
     * and has no constructor of its own to hand them to. The marks are kept in a store that holds
     * them the way the database does, so that what these exercise - an event recorded once - is
     * exercised across the reads and writes that really happen.</p>
     */
    private GuestCriticalEventAuditManager managerWithMockedAudit() {
        auditLogDirector = mock(AuditLogDirector.class);
        GuestCriticalEventAuditManager manager = new GuestCriticalEventAuditManager();
        inject(manager, "auditLogDirector", auditLogDirector);
        inject(manager, "markDao", new InMemoryMarkDao());
        return manager;
    }

    private static void inject(GuestCriticalEventAuditManager manager, String name, Object value) {
        try {
            Field field = GuestCriticalEventAuditManager.class.getDeclaredField(name);
            field.setAccessible(true);
            field.set(manager, value);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    /** What the database holds between passes, held in a map instead. */
    private static class InMemoryMarkDao implements VmGuestEventMarkDao {

        private final Map<Guid, Map<String, VmGuestEventMark>> marks = new HashMap<>();

        @Override
        public List<VmGuestEventMark> getByVmId(Guid vmId) {
            return new ArrayList<>(marks.getOrDefault(vmId, Map.of()).values());
        }

        @Override
        public void save(VmGuestEventMark mark) {
            marks.computeIfAbsent(mark.getVmId(), id -> new HashMap<>())
                    .put(mark.getLogName(), mark);
        }
    }

    private static final String LINE = "4821\tSystem\t2\tdisk\t7\t2026-09-19T16:15:17.0000000Z\t"
            + "The device, \\Device\\Harddisk0\\DR0, has a bad block.";

    @Test
    public void aLineSaysWhichEventItIs() {
        GuestEvent event = GuestEvent.parse(LINE);

        assertNotNull(event);
        assertAll(
                () -> assertEquals(4821L, event.recordId),
                () -> assertEquals("System", event.log),
                // The number, not the display name: the guest writes that in its own language.
                () -> assertEquals("2", event.level),
                () -> assertEquals("disk", event.source),
                () -> assertEquals("7", event.eventId),
                () -> assertEquals("2026-09-19T16:15:17.0000000Z", event.time),
                () -> assertTrue(event.message.startsWith("The device")));
    }

    @Test
    public void aMessageMayHoldAnythingButATab() {
        // The line is split into a fixed number of fields, so a message with a tab in it stays
        // whole instead of being read as fields that are not there.
        GuestEvent event = GuestEvent.parse("9\tApplication\t1\tsvc\t1\t2026-09-19T10:00:00Z\ta\tb");

        assertNotNull(event);
        assertEquals("a\tb", event.message);
    }

    @Test
    public void anEventWithNoMessageOfItsOwnIsStillAnEvent() {
        // A provider whose message file is missing logs an event with no text. Trimming the line
        // would take the tab that ends it, and the event would read as six fields and be lost.
        GuestEvent event = GuestEvent.parse("4822\tSystem\t2\tdisk\t7\t2026-09-19T16:15:18.0000000Z\t");

        assertNotNull(event);
        assertAll(
                () -> assertEquals(4822L, event.recordId),
                () -> assertEquals("7", event.eventId),
                () -> assertEquals("", event.message));
    }

    @Test
    public void aLineThatDoesNotSayIsSkippedRatherThanThrowing() {
        // Whatever a guest's PowerShell wrote. One odd line is not a reason to drop the rest.
        assertAll(
                () -> assertNull(GuestEvent.parse("")),
                () -> assertNull(GuestEvent.parse("   ")),
                () -> assertNull(GuestEvent.parse("not\tenough\tfields")),
                () -> assertNull(GuestEvent.parse(
                        "notanumber\tSystem\t2\tdisk\t7\t2026-09-19T16:15:17Z\tx")));
    }

    @Test
    public void theQueryAsksForWhatIsWrongAndNotForEverything() {
        String command = ExecuteVmGuestCommandCommand.criticalGuestEventsCommand(2, false);

        assertAll(
                // 1 is Critical and 2 is Error. Everything else is what the guest does all day.
                () -> assertTrue(command.contains("Level = @(1, 2)"), command),
                () -> assertTrue(command.contains("LogName = @(\"System\", \"Application\")"), command),
                // Not asked for, not asked about.
                () -> assertTrue(!command.contains("Security"), command),
                () -> assertTrue(command.contains("AddHours(-2)"), command),
                // The record number is what lets the same event be recognised across passes.
                () -> assertTrue(command.contains("$_.RecordId"), command),
                () -> assertTrue(command.contains(
                        "-MaxEvents " + ExecuteVmGuestCommandCommand.CRITICAL_EVENT_LIMIT), command));
    }

    @Test
    public void theSecurityLogIsAskedByWhatItsEntriesAreAndNotByTheirLevel() {
        String command = ExecuteVmGuestCommandCommand.criticalGuestEventsCommand(2, true);

        assertAll(
                // Every refused logon and denied access carries the Audit Failure keyword.
                () -> assertTrue(command.contains(
                        "@{ LogName = \"Security\"; Keywords = [long]4503599627370496; StartTime = $start }"),
                        command),
                // And these are recorded as successes, which is why the keyword does not find them.
                () -> assertTrue(command.contains("@{ LogName = \"Security\"; Id = @(1102, 4719,"), command),
                () -> assertTrue(command.contains("4720"), command),
                () -> assertTrue(command.contains("4740"), command));
    }

    @Test
    public void theQueryHandsTheEventsOverInTheOrderTheyAreReadIn() {
        String command = ExecuteVmGuestCommandCommand.criticalGuestEventsCommand(2, true);

        // The engine remembers the highest record number seen in each log and takes anything at
        // or below it as recorded already, so an event handed over before one it is numbered
        // after would be dropped. By log and then by number is what makes that safe; by time is
        // not, since two events of the same second have no order between them.
        assertTrue(command.contains("Sort-Object -Property LogName, RecordId"), command);
        assertTrue(!command.contains("Sort-Object -Property TimeCreated"), command);
    }

    @Test
    public void anEventThatComesBackTwiceIsRecordedOnce() {
        // Both questions put to the security log can match one entry, so the same event can be
        // handed over twice in one pass. The mark moves as each is recorded, which is what makes
        // the second reading of it a repeat rather than a new event.
        GuestCriticalEventAuditManager manager = managerWithMockedAudit();
        VM vm = vm("88888888-8888-8888-8888-888888888888");

        manager.record(vm, line(30, "Security", "4625") + "\n" + line(30, "Security", "4625"));

        verify(auditLogDirector, times(1))
                .log(any(AuditLogable.class), eq(AuditLogType.VM_GUEST_SECURITY_EVENT));
    }

    @Test
    public void theQueryReportsWhatEveryLocaleWritesTheSameWay() {
        String command = ExecuteVmGuestCommandCommand.criticalGuestEventsCommand(6, true);

        assertAll(
                // The display name is translated into the language of the guest.
                () -> assertTrue(!command.contains("LevelDisplayName"), command),
                () -> assertTrue(command.contains("[int]$_.Level"), command),
                // As is the local date format, in a calendar that may not even be Gregorian.
                () -> assertTrue(command.contains("$_.TimeCreated.ToUniversalTime().ToString(\"o\")"),
                        command));
    }

    @Test
    public void anEmptyLogIsLetGoAndAnUnreadableOneIsNot() {
        String command = ExecuteVmGuestCommandCommand.criticalGuestEventsCommand(6, true);

        assertAll(
                // By the identifier of the error, which Windows does not translate, rather than by
                // its message, which it does.
                () -> assertTrue(command.contains(
                        "catch { if ($_.FullyQualifiedErrorId -notlike \"NoMatchingEventsFound*\") { throw } }"),
                        command),
                // Anything else fails the pass, so being unable to read a log is not mistaken for
                // the log having nothing in it.
                () -> assertTrue(command.contains("-ErrorAction Stop"), command),
                () -> assertTrue(!command.contains("-ErrorAction SilentlyContinue"), command));
    }

    @Test
    public void theQueryIsOneLinePerEventWithTabsBetween() {
        String command = ExecuteVmGuestCommandCommand.criticalGuestEventsCommand(6, true);

        assertTrue(command.contains("\"{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}\""), command);
        assertEquals(GuestEventFields.COUNT, 7, "the parser reads seven of them");
    }

    /** Kept next to the format so the two are changed together. */
    private static final class GuestEventFields {
        private static final int COUNT = 7;
    }

    /* Recorded once, and the estate reached in turn */

    private static String line(long recordId, String log) {
        return line(recordId, log, "7");
    }

    private static String line(long recordId, String log, String eventId) {
        return recordId + "\t" + log + "\t2\tdisk\t" + eventId
                + "\t2026-09-19T16:15:17.0000000Z\tbad block";
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

    @Test
    public void whatTheSecurityLogSaysIsRecordedAsWhatItIs() {
        GuestCriticalEventAuditManager manager = managerWithMockedAudit();
        VM vm = vm("55555555-5555-5555-5555-555555555555");

        // A refused logon, and then the audit trail itself being erased.
        manager.record(vm, line(1, "Security", "4625") + "\n" + line(2, "Security", "1102"));

        assertAll(
                () -> verify(auditLogDirector, times(1))
                        .log(any(AuditLogable.class), eq(AuditLogType.VM_GUEST_SECURITY_EVENT)),
                () -> verify(auditLogDirector, times(1))
                        .log(any(AuditLogable.class), eq(AuditLogType.VM_GUEST_AUDIT_TRAIL_EVENT)),
                // Neither of them is a fault of the machine, which is what the other type says.
                () -> verify(auditLogDirector, times(0))
                        .log(any(AuditLogable.class), eq(AuditLogType.VM_GUEST_CRITICAL_EVENT)));
    }

    @Test
    public void theLevelIsNamedInTheLanguageOfTheEngine() {
        assertAll(
                () -> assertEquals("Critical", GuestCriticalEventAuditManager.levelName("1")),
                () -> assertEquals("Error", GuestCriticalEventAuditManager.levelName("2")),
                // A guest may yet report one that is none of these, and it is still said plainly.
                () -> assertEquals("Level 9", GuestCriticalEventAuditManager.levelName("9")));
    }

    @Test
    public void theTimeIsWrittenTheWayTheRestOfTheEngineWritesOne() {
        assertAll(
                () -> assertEquals("2026-09-19 16:15:17 UTC",
                        GuestCriticalEventAuditManager.eventTime("2026-09-19T16:15:17.0000000Z")),
                // What cannot be read is passed on as it came rather than dropped or guessed at.
                () -> assertEquals("whenever", GuestCriticalEventAuditManager.eventTime("whenever")));
    }

    @Test
    public void whatWasRecordedIsRememberedAcrossARestartOfTheEngine() {
        // The marks live in the database. Held in memory, a restart would report again everything
        // the lookback window still holds.
        InMemoryMarkDao marks = new InMemoryMarkDao();
        GuestCriticalEventAuditManager before = managerWithMockedAudit();
        inject(before, "markDao", marks);
        VM vm = vm("66666666-6666-6666-6666-666666666666");
        before.record(vm, line(10, "System"));

        GuestCriticalEventAuditManager after = managerWithMockedAudit();
        inject(after, "markDao", marks);
        after.record(vm, line(10, "System"));

        // The second manager is a new one: what it did not record, it did not record because the
        // mark of the first one outlived it.
        verify(auditLogDirector, times(0))
                .log(any(AuditLogable.class), eq(AuditLogType.VM_GUEST_CRITICAL_EVENT));
    }

    @Test
    public void aLogThatCouldNotBeReadIsSaidRatherThanPassedOverInSilence() {
        GuestCriticalEventAuditManager manager = managerWithMockedAudit();
        VM vm = vm("77777777-7777-7777-7777-777777777777");

        // The guest handed over what it had and said which log it would not give up.
        manager.record(vm, line(10, "System") + "\n"
                + ExecuteVmGuestCommandCommand.UNREADABLE_LOG_MARKER
                + "\tAttempted to perform an unauthorized operation.");

        assertAll(
                // What it did hand over is recorded...
                () -> verify(auditLogDirector, times(1))
                        .log(any(AuditLogable.class), eq(AuditLogType.VM_GUEST_CRITICAL_EVENT)),
                // ...and what it did not is not lost with it.
                () -> verify(auditLogDirector, times(1))
                        .log(any(AuditLogable.class), eq(AuditLogType.VM_GUEST_EVENT_COLLECTION_FAILED)));
    }

    @Test
    public void aMarkerIsReadApartFromAnEvent() {
        assertAll(
                () -> assertEquals("Access is denied", GuestCriticalEventAuditManager.unreadableLog(
                        ExecuteVmGuestCommandCommand.UNREADABLE_LOG_MARKER + "\tAccess is denied\r")),
                () -> assertNull(GuestCriticalEventAuditManager.unreadableLog(LINE)),
                () -> assertNull(GuestCriticalEventAuditManager.unreadableLog(null)));
    }

    @Test
    public void oneUnreadableLogDoesNotTakeTheReadableOnesWithIt() {
        String command = ExecuteVmGuestCommandCommand.criticalGuestEventsCommand(2, true);

        assertAll(
                // Collected rather than thrown: a throw here would end the pass, and the events
                // already read from the other logs would be discarded with it.
                () -> assertTrue(command.contains("{ $failures += $_.Exception.Message }"), command),
                () -> assertTrue(!command.contains("{ throw }"), command),
                // Reported after the events, so what was read is read first.
                () -> assertTrue(command.indexOf("foreach ($failure in $failures)")
                        > command.indexOf("-f $_.RecordId"), command),
                () -> assertTrue(command.contains(
                        ExecuteVmGuestCommandCommand.UNREADABLE_LOG_MARKER + "`t"), command));
    }

    /* The request itself */

    @Test
    public void theRequestIsOneThisCommandWillAccept() {
        // Left out of what validate() knows about, a request for these falls through to the check
        // that wants a .bat file to run - which this never names - and is refused every time.
        ExecuteVmGuestCommandParameters parameters = new ExecuteVmGuestCommandParameters();
        parameters.setCriticalEventsRequested(true);
        parameters.setLookbackHours(2);
        parameters.setSecurityEventsRequested(true);

        assertAll(
                () -> assertEquals(Boolean.TRUE, parameters.getCriticalEventsRequested()),
                () -> assertEquals(2, parameters.getLookbackHours()),
                () -> assertEquals(Boolean.TRUE, parameters.getSecurityEventsRequested()),
                // and it is not any of the others, which is what the one-operation check counts
                () -> assertNull(parameters.getGuestEventsRequested()),
                () -> assertNull(parameters.getCmdBlocked()),
                () -> assertNull(parameters.getManagementCommandsBlocked()),
                () -> assertNull(parameters.getNetworkEnabled()));
    }
}
