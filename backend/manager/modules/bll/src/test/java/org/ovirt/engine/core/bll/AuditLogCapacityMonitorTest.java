package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.ovirt.engine.core.common.businessentities.AuditLogCapacityStatus;
import org.ovirt.engine.core.common.config.Config;
import org.ovirt.engine.core.common.config.ConfigCommon;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.utils.MockConfigDescriptor;
import org.ovirt.engine.core.utils.MockConfigExtension;

@ExtendWith({ MockConfigExtension.class, MockitoExtension.class })
@MockitoSettings(strictness = Strictness.LENIENT)
class AuditLogCapacityMonitorTest {

    /** A limit small enough that a file of a few bytes moves the reading across the thresholds. */
    private static final long LIMIT_MIB = 1;

    private static final long LIMIT_BYTES = LIMIT_MIB * 1024L * 1024L;

    @TempDir
    Path temporaryDirectory;

    @Mock
    private AuditLogDirector auditLogDirector;

    @InjectMocks
    private AuditLogCapacityMonitor monitor;

    public static Stream<MockConfigDescriptor<?>> mockConfiguration() {
        return Stream.of(
                MockConfigDescriptor.of(ConfigValues.ENGINE_AUDIT_LOG_MAX_SIZE_MB, LIMIT_MIB),
                MockConfigDescriptor.of(ConfigValues.ENGINE_AUDIT_LOG_CAPACITY_CHECK_INTERVAL_SECONDS, 60L),
                MockConfigDescriptor.of(ConfigValues.ENGINE_AUDIT_LOG_DIR, ""));
    }

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
    void namesTheStateTheReadingIsIn() {
        assertEquals(AuditLogCapacityStatus.State.NORMAL,
                AuditLogCapacityMonitor.capacityState(94, 100));
        assertEquals(AuditLogCapacityStatus.State.WARNING,
                AuditLogCapacityMonitor.capacityState(95, 100));
        assertEquals(AuditLogCapacityStatus.State.EXCEEDED,
                AuditLogCapacityMonitor.capacityState(100, 100));
        // Over the limit is still EXCEEDED, not a second, worse thing.
        assertEquals(AuditLogCapacityStatus.State.EXCEEDED,
                AuditLogCapacityMonitor.capacityState(150, 100));
    }

    @Test
    void barIsNotDrawnLongerThanTheBoxItIsDrawnIn() {
        AuditLogCapacityStatus status = new AuditLogCapacityStatus();
        status.setMaxBytes(100);

        status.setUsedBytes(30);
        assertEquals(30, status.getUsedPercent());
        // The space in use can pass the limit; a bar wider than the box it is drawn in reads as a
        // rendering fault rather than as the fact it is reporting.
        status.setUsedBytes(150);
        assertEquals(100, status.getUsedPercent());
        // And a limit of zero is monitoring switched off, not a division.
        status.setMaxBytes(0);
        assertEquals(0, status.getUsedPercent());
    }

    @Test
    void saysMonitoringIsOffRatherThanShowingAnEmptyStorage() {
        // configure() has not been called, which is the same state a screen sees on a host whose
        // limit or interval is set to zero. An administrator has to be told that, rather than left
        // to infer it from a panel showing nothing.
        AuditLogCapacityStatus status = monitor.getStatus();

        assertEquals(AuditLogCapacityStatus.State.DISABLED, status.getState());
        assertFalse(status.isMeasured());
        assertNull(status.getMeasuredAt());
    }

    @Test
    void readsTheLimitAndThePathTheConfigurationNames() {
        assertTrue(configure());

        AuditLogCapacityStatus status = monitor.getStatus();
        assertEquals(temporaryDirectory.toString(), status.getDirectory());
        assertEquals(LIMIT_BYTES, status.getMaxBytes());
        assertEquals(60, status.getCheckIntervalSeconds());
        assertEquals(AuditLogCapacityMonitor.WARNING_REMAINING_PERCENT,
                status.getWarningRemainingPercent());
    }

    @Test
    void measuresOnDemandWhenTheMonitorHasNotMeasuredYet() throws IOException {
        Files.write(temporaryDirectory.resolve("engine.log"), new byte[(int) (LIMIT_BYTES / 4)]);
        configure();

        AuditLogCapacityStatus status = monitor.getStatus();

        // A screen opened in the first minute after a start would otherwise show nothing at all.
        assertTrue(status.isMeasuredOnDemand());
        assertEquals(AuditLogCapacityStatus.State.NORMAL, status.getState());
        assertEquals(LIMIT_BYTES / 4, status.getUsedBytes());
        assertEquals(75, status.getRemainingPercent());
        assertNotNull(status.getMeasuredAt());
        // Kept, so a second screen opened a moment later does not walk the directory again.
        assertFalse(monitor.getStatus().isMeasuredOnDemand());
    }

    @Test
    void showsWhatTheScheduledPassMeasured() throws IOException {
        // 96% of the limit: inside it, and within the margin the engine warns at.
        Files.write(temporaryDirectory.resolve("engine.log"), new byte[(int) (LIMIT_BYTES / 100 * 96)]);
        configure();

        monitor.checkCapacity(temporaryDirectory, LIMIT_BYTES);
        AuditLogCapacityStatus status = monitor.getStatus();

        assertFalse(status.isMeasuredOnDemand());
        assertEquals(AuditLogCapacityStatus.State.WARNING, status.getState());
        assertEquals(4, status.getRemainingPercent());
    }

    @Test
    void reportsTheLimitBeingReachedAsReachedAndNotAsAWarning() throws IOException {
        Files.write(temporaryDirectory.resolve("engine.log"), new byte[(int) LIMIT_BYTES]);
        configure();

        monitor.checkCapacity(temporaryDirectory, LIMIT_BYTES);
        AuditLogCapacityStatus status = monitor.getStatus();

        assertEquals(AuditLogCapacityStatus.State.EXCEEDED, status.getState());
        assertEquals(0, status.getRemainingPercent());
        assertEquals(100, status.getUsedPercent());
    }

    @Test
    void aMeasurementThatCouldNotBeTakenIsNotReportedAsAnEmptyStorage() throws IOException {
        Files.write(temporaryDirectory.resolve("engine.log"), new byte[16]);
        configure();
        monitor.checkCapacity(temporaryDirectory, LIMIT_BYTES);
        assertTrue(monitor.getStatus().isMeasured());

        monitor.checkCapacity(temporaryDirectory.resolve("no-such-directory"), LIMIT_BYTES);

        // Leaving the last figure standing would show a size from before the directory became
        // unreadable, with nothing to say that it is no longer being measured.
        AuditLogCapacityStatus status = monitor.getStatus();
        assertEquals(AuditLogCapacityStatus.State.UNAVAILABLE, status.getState());
        assertFalse(status.isMeasured());
        assertTrue(status.getUnavailableReason().contains("IOException"),
                status.getUnavailableReason());
    }

    @Test
    void calculatesRegularFilesRecursivelyWithoutFollowingSymbolicLinks() throws IOException {
        Files.write(temporaryDirectory.resolve("engine.log"), new byte[11]);
        Path archive = Files.createDirectory(temporaryDirectory.resolve("archive"));
        Files.write(archive.resolve("engine.log.1"), new byte[17]);
        Files.createSymbolicLink(temporaryDirectory.resolve("archive-link"), archive);

        assertEquals(28, AuditLogCapacityMonitor.calculateDirectorySize(temporaryDirectory));
    }

    /**
     * Reads the configuration, with the watched directory pointed at this test's own.
     *
     * <p>mockConfiguration() is static and runs before the temporary directory exists, so it can
     * name every value but this one; this one is stubbed here, where the directory does exist.</p>
     */
    private boolean configure() {
        doReturn(temporaryDirectory.toString())
                .when(Config.getConfigUtils())
                .getValue(ConfigValues.ENGINE_AUDIT_LOG_DIR, ConfigCommon.defaultConfigurationVersion);
        return monitor.configure();
    }
}
