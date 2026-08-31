package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuditLogCapacityMonitorTest {

    @TempDir
    Path temporaryDirectory;

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

    @Test
    void calculatesRegularFilesRecursivelyWithoutFollowingSymbolicLinks() throws IOException {
        Files.write(temporaryDirectory.resolve("engine.log"), new byte[11]);
        Path archive = Files.createDirectory(temporaryDirectory.resolve("archive"));
        Files.write(archive.resolve("engine.log.1"), new byte[17]);
        Files.createSymbolicLink(temporaryDirectory.resolve("archive-link"), archive);

        assertEquals(28, AuditLogCapacityMonitor.calculateDirectorySize(temporaryDirectory));
    }
}
