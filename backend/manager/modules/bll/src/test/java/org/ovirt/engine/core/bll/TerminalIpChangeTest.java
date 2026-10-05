package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.common.AuditLogType;

/**
 * The screen sends the whole list for every operation; the record has to say which one it was.
 */
public class TerminalIpChangeTest {

    private static final String REGISTERED = "127.0.0.1\n192.168.40.10\n192.168.40.11";

    @Test
    void registeringOneAddressIsRecordedAsARegistration() {
        TerminalIpChange change = TerminalIpChange.between(REGISTERED,
                "127.0.0.1\n192.168.40.10\n192.168.40.11\n192.168.40.12");
        assertEquals(TerminalIpChange.Kind.ADDED, change.getKind());
        assertEquals(List.of("192.168.40.12"), change.getAdded());
        assertEquals(AuditLogType.TERMINAL_IP_AUTH_ADDED,
                SetTerminalIpAuthCommand.auditLogTypeOf(change.getKind(), true));
    }

    @Test
    void replacingOneAddressIsRecordedAsAChangeFromOldToNew() {
        TerminalIpChange change = TerminalIpChange.between(REGISTERED,
                "127.0.0.1\n192.168.40.20\n192.168.40.11");
        assertEquals(TerminalIpChange.Kind.CHANGED, change.getKind());
        assertEquals(List.of("192.168.40.20"), change.getAdded());
        assertEquals(List.of("192.168.40.10"), change.getRemoved());
        assertEquals(AuditLogType.TERMINAL_IP_AUTH_CHANGED,
                SetTerminalIpAuthCommand.auditLogTypeOf(change.getKind(), true));
    }

    @Test
    void deletingOneAddressIsRecordedAsARemoval() {
        TerminalIpChange change = TerminalIpChange.between(REGISTERED, "127.0.0.1\n192.168.40.11");
        assertEquals(TerminalIpChange.Kind.REMOVED, change.getKind());
        assertEquals(List.of("192.168.40.10"), change.getRemoved());
        assertEquals(AuditLogType.TERMINAL_IP_AUTH_REMOVED,
                SetTerminalIpAuthCommand.auditLogTypeOf(change.getKind(), true));
    }

    @Test
    void theLoopbackAddressIsNeverReported() {
        // The screen does not have to send it; the engine always keeps it.
        TerminalIpChange change = TerminalIpChange.between(REGISTERED, "192.168.40.10\n192.168.40.11");
        assertEquals(TerminalIpChange.Kind.OTHER, change.getKind());
        assertEquals("no address added or removed", change.describe());
    }

    @Test
    void aRefusedWriteIsRecordedAsTheOperationThatWasRefused() {
        assertEquals(AuditLogType.TERMINAL_IP_AUTH_ADD_FAILED,
                SetTerminalIpAuthCommand.auditLogTypeOf(TerminalIpChange.Kind.ADDED, false));
        assertEquals(AuditLogType.TERMINAL_IP_AUTH_CHANGE_FAILED,
                SetTerminalIpAuthCommand.auditLogTypeOf(TerminalIpChange.Kind.CHANGED, false));
        assertEquals(AuditLogType.TERMINAL_IP_AUTH_REMOVE_FAILED,
                SetTerminalIpAuthCommand.auditLogTypeOf(TerminalIpChange.Kind.REMOVED, false));
    }

    @Test
    void severalAddressesAtOnceAreListedInTheGeneralRecord() {
        TerminalIpChange change = TerminalIpChange.between(REGISTERED,
                "127.0.0.1\n192.168.40.20\n192.168.40.21");
        assertEquals(TerminalIpChange.Kind.OTHER, change.getKind());
        assertEquals("added: 192.168.40.20, 192.168.40.21; removed: 192.168.40.10, 192.168.40.11",
                change.describe());
        assertEquals(AuditLogType.TERMINAL_IP_AUTH_CONFIG_UPDATED,
                SetTerminalIpAuthCommand.auditLogTypeOf(change.getKind(), true));
    }

    @Test
    void nothingRegisteredYetCountsAsRegistration() {
        TerminalIpChange change = TerminalIpChange.between(null, "192.168.40.10");
        assertEquals(TerminalIpChange.Kind.ADDED, change.getKind());
    }
}
