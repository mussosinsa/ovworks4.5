package org.ovirt.engine.core.bll;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

import javax.inject.Singleton;

import org.ovirt.engine.core.bll.AuditStorageUsage.Target;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Measures the file systems under the audit records through the root storage helper. The engine
 * runs as ovirt and cannot read the PostgreSQL data directory, which is private to postgres, nor
 * the server settings that say where it is; the helper can.
 */
@Singleton
public class AuditStorageHelper {

    static final String SUDO_COMMAND = "/usr/bin/sudo"; //$NON-NLS-1$
    static final String HELPER = "/usr/share/ovirt-engine/bin/audit-storage-usage.py"; //$NON-NLS-1$
    private static final long TIMEOUT_SECONDS = 60;
    private static final Logger log = LoggerFactory.getLogger(AuditStorageHelper.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * What the helper measured, or why it could not.
     */
    public static final class Report {
        private final List<AuditStorageUsage> usages;
        private final List<String> maintenanceWarnings;
        private final Reserve reserve;
        private final boolean walOnDataFilesystem;

        Report(List<AuditStorageUsage> usages, List<String> maintenanceWarnings) {
            this(usages, maintenanceWarnings, Reserve.NONE, false);
        }

        Report(List<AuditStorageUsage> usages, List<String> maintenanceWarnings, Reserve reserve,
                boolean walOnDataFilesystem) {
            this.usages = Collections.unmodifiableList(usages);
            this.maintenanceWarnings = Collections.unmodifiableList(maintenanceWarnings);
            this.reserve = reserve;
            this.walOnDataFilesystem = walOnDataFilesystem;
        }

        /**
         * @return the emergency reserve file on the database file system, as the helper left it
         */
        public Reserve getReserve() {
            return reserve;
        }

        /**
         * @return whether pg_wal is on the file system of the data directory, where a full file
         *         system stops PostgreSQL instead of failing the writes
         */
        public boolean isWalOnDataFilesystem() {
            return walOnDataFilesystem;
        }

        public List<AuditStorageUsage> getUsages() {
            return usages;
        }

        public List<String> getMaintenanceWarnings() {
            return maintenanceWarnings;
        }
    }

    /**
     * The emergency reserve file the helper keeps on the database file system and removes at the
     * critical level, so that PostgreSQL has room to keep writing while the storage is expanded.
     */
    public static final class Reserve {
        /** Not measured: the database is on another server, or the helper did not say. */
        public static final String UNAVAILABLE = "unavailable"; //$NON-NLS-1$
        public static final String PRESENT = "present"; //$NON-NLS-1$
        /** Removed at the critical level and not yet put back. */
        public static final String RELEASED = "released"; //$NON-NLS-1$
        /** Never created: creating it would have taken the file system over the high level. */
        public static final String INSUFFICIENT = "insufficient"; //$NON-NLS-1$
        public static final String DISABLED = "disabled"; //$NON-NLS-1$
        public static final String ERROR = "error"; //$NON-NLS-1$
        public static final String BUSY = "busy"; //$NON-NLS-1$

        static final Reserve NONE = new Reserve(UNAVAILABLE, "", 0, "", "", -1); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

        private final String state;
        private final String path;
        private final long sizeBytes;
        private final String action;
        private final String detail;
        private final double releasedPercent;

        Reserve(String state, String path, long sizeBytes, String action, String detail, double releasedPercent) {
            this.state = state == null || state.isEmpty() ? UNAVAILABLE : state;
            this.path = path == null ? "" : path; //$NON-NLS-1$
            this.sizeBytes = sizeBytes;
            this.action = action == null ? "" : action; //$NON-NLS-1$
            this.detail = detail == null ? "" : detail; //$NON-NLS-1$
            this.releasedPercent = releasedPercent;
        }

        static Reserve of(JsonNode node) {
            if (node == null || !node.isObject()) {
                return NONE;
            }
            return new Reserve(node.path("state").asText(UNAVAILABLE), //$NON-NLS-1$
                    node.path("path").asText(""), //$NON-NLS-1$ //$NON-NLS-2$
                    node.path("size_bytes").asLong(0), //$NON-NLS-1$
                    node.path("action").asText(""), //$NON-NLS-1$ //$NON-NLS-2$
                    node.path("detail").asText(""), //$NON-NLS-1$ //$NON-NLS-2$
                    node.path("released_percent").asDouble(-1)); //$NON-NLS-1$
        }

        public String getState() {
            return state;
        }

        public String getPath() {
            return path;
        }

        public long getSizeBytes() {
            return sizeBytes;
        }

        /**
         * @return what the helper did on this run - created, restored, released or removed - or
         *         an empty string
         */
        public String getAction() {
            return action;
        }

        public String getDetail() {
            return detail;
        }

        public double getReleasedPercent() {
            return releasedPercent;
        }

        /**
         * @return what the capacity screen says about it
         */
        public String describe() {
            switch (state) {
            case PRESENT:
                return "비상 예비 공간 " + formatBytes(sizeBytes) + " 확보 (" + path + ")"; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            case RELEASED:
                return "비상 예비 공간 해제됨 (" + path + "): 위기 수준에서 " + formatBytes(sizeBytes) //$NON-NLS-1$ //$NON-NLS-2$
                        + "를 비웠습니다. 저장소를 즉시 증설하십시오."; //$NON-NLS-1$
            case INSUFFICIENT:
            case ERROR:
                return "비상 예비 공간 없음: " + detail; //$NON-NLS-1$
            case DISABLED:
                return "비상 예비 공간 사용 안 함 (AUDIT_STORAGE_RESERVE_MB=0)"; //$NON-NLS-1$
            default:
                return ""; //$NON-NLS-1$
            }
        }
    }

    /**
     * @param logDirectory
     *            the directory whose file system holds the engine and PostgreSQL logs
     * @param dataDirectory
     *            the PostgreSQL data directory, or empty for the helper to find a local one
     * @param backupDirectory
     *            the configured backup directory, or empty
     * @param selectedDirectory
     *            the backup directory typed on the protection tab, or empty
     */
    public Report measure(String logDirectory, String dataDirectory, String backupDirectory,
            String selectedDirectory, AuditStorageThresholds thresholds) {
        List<String> command = buildCommand(logDirectory, dataDirectory, backupDirectory, selectedDirectory,
                thresholds);
        String output;
        try {
            output = run(command);
        } catch (IOException | RuntimeException exception) {
            log.debug("Audit storage helper failed", exception);
            return failed(exception.getMessage(), backupDirectory, selectedDirectory);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return failed("측정이 중단되었습니다.", backupDirectory, selectedDirectory); //$NON-NLS-1$
        }
        try {
            return parse(output, thresholds, backupDirectory, selectedDirectory);
        } catch (IOException | RuntimeException exception) {
            log.error("Unable to read the audit storage helper output: {}", output, exception);
            return failed("저장소 측정 결과를 해석할 수 없습니다.", backupDirectory, selectedDirectory); //$NON-NLS-1$
        }
    }

    static List<String> buildCommand(String logDirectory, String dataDirectory, String backupDirectory,
            String selectedDirectory) {
        return buildCommand(logDirectory, dataDirectory, backupDirectory, selectedDirectory, null);
    }

    /**
     * @param thresholds
     *            the levels the helper releases the emergency reserve at, or {@code null} for its
     *            own defaults
     */
    static List<String> buildCommand(String logDirectory, String dataDirectory, String backupDirectory,
            String selectedDirectory, AuditStorageThresholds thresholds) {
        List<String> command = new ArrayList<>();
        command.add(SUDO_COMMAND);
        command.add("-n"); //$NON-NLS-1$
        command.add(HELPER);
        command.add("usage"); //$NON-NLS-1$
        command.add("--log-dir"); //$NON-NLS-1$
        command.add(logDirectory);
        addOption(command, "--data-dir", dataDirectory); //$NON-NLS-1$
        addOption(command, "--backup-dir", backupDirectory); //$NON-NLS-1$
        addOption(command, "--selected-dir", selectedDirectory); //$NON-NLS-1$
        if (thresholds != null) {
            addOption(command, "--thresholds", thresholds.toString()); //$NON-NLS-1$
        }
        return command;
    }

    private static void addOption(List<String> command, String option, String value) {
        if (value != null && !value.trim().isEmpty()) {
            command.add(option);
            command.add(value.trim());
        }
    }

    String run(List<String> command) throws IOException, InterruptedException {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(false);
        builder.redirectError(ProcessBuilder.Redirect.DISCARD);
        Process process = builder.start();
        process.getOutputStream().close();
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> copy(process.getInputStream(), stdout), "audit-storage-helper"); //$NON-NLS-1$
        reader.setDaemon(true);
        reader.start();
        if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("저장소 측정 헬퍼가 " + TIMEOUT_SECONDS + "초 안에 끝나지 않았습니다."); //$NON-NLS-1$ //$NON-NLS-2$
        }
        reader.join(TimeUnit.SECONDS.toMillis(5));
        String output = new String(stdout.toByteArray(), StandardCharsets.UTF_8).trim();
        if (process.exitValue() != 0 && output.isEmpty()) {
            throw new IOException("저장소 측정 헬퍼 실행 실패 (종료 코드 " + process.exitValue() //$NON-NLS-1$
                    + "). sudo 설정(/etc/sudoers.d/ovirt-backup)을 확인하십시오."); //$NON-NLS-1$
        }
        return output;
    }

    private static void copy(InputStream input, ByteArrayOutputStream output) {
        byte[] buffer = new byte[8192];
        try (InputStream in = input) {
            int read;
            while ((read = in.read(buffer)) >= 0) {
                synchronized (output) {
                    output.write(buffer, 0, read);
                }
            }
        } catch (IOException exception) {
            log.debug("Unable to read the audit storage helper output", exception);
        }
    }

    static Report parse(String output, AuditStorageThresholds thresholds, String backupDirectory,
            String selectedDirectory) throws IOException {
        JsonNode root = mapper.readTree(output);
        if (root == null || !root.isObject()) {
            throw new IOException("unexpected helper output"); //$NON-NLS-1$
        }
        List<AuditStorageUsage> usages = new ArrayList<>();
        JsonNode filesystems = root.path("filesystems"); //$NON-NLS-1$
        usages.add(filesystem(Target.DB_FILESYSTEM, filesystems.path("db"), thresholds)); //$NON-NLS-1$
        usages.add(wal(root.path("wal"))); //$NON-NLS-1$
        usages.add(filesystem(Target.LOG_FILESYSTEM, filesystems.path("log"), thresholds)); //$NON-NLS-1$
        if (isSet(backupDirectory)) {
            usages.add(filesystem(Target.BACKUP_FILESYSTEM, filesystems.path("backup"), thresholds)); //$NON-NLS-1$
        }
        if (isSet(selectedDirectory)) {
            usages.add(filesystem(Target.SELECTED_BACKUP_FILESYSTEM, filesystems.path("selected"), thresholds)); //$NON-NLS-1$
        }
        List<String> warnings = new ArrayList<>();
        for (JsonNode warning : root.path("maintenance_warnings")) { //$NON-NLS-1$
            warnings.add(warning.asText());
        }
        return new Report(usages, warnings, Reserve.of(root.get("reserve")), //$NON-NLS-1$
                root.path("wal").path("same_filesystem").asBoolean(false)); //$NON-NLS-1$ //$NON-NLS-2$
    }

    private static AuditStorageUsage filesystem(Target target, JsonNode node, AuditStorageThresholds thresholds) {
        String path = node.path("path").asText(""); //$NON-NLS-1$ //$NON-NLS-2$
        if (node.path("expected").asBoolean(false)) { //$NON-NLS-1$
            return AuditStorageUsage.unavailable(target, path, node.path("error").asText("")); //$NON-NLS-1$ //$NON-NLS-2$
        }
        if (node.isMissingNode() || node.has("error")) { //$NON-NLS-1$
            return AuditStorageUsage.unknown(target, path,
                    node.path("error").asText("헬퍼가 측정 결과를 보내지 않았습니다.")); //$NON-NLS-1$ //$NON-NLS-2$
        }
        long used = node.path("used_bytes").asLong(); //$NON-NLS-1$
        long available = node.path("available_bytes").asLong(); //$NON-NLS-1$
        StringBuilder detail = new StringBuilder();
        String mount = node.path("mount").asText(""); //$NON-NLS-1$ //$NON-NLS-2$
        if (!mount.isEmpty()) {
            detail.append("마운트 ").append(mount); //$NON-NLS-1$
        }
        if (node.has("inode_used_percent")) { //$NON-NLS-1$
            if (detail.length() > 0) {
                detail.append(", "); //$NON-NLS-1$
            }
            detail.append("inode 사용률 ") //$NON-NLS-1$
                    .append(AuditStorageSnapshot.formatPercent(node.path("inode_used_percent").asDouble())) //$NON-NLS-1$
                    .append('%');
        }
        // A file system that runs out of inodes refuses writes as surely as one without space, so
        // the more used of the two decides the level.
        double spacePercent = AuditStorageUsage.usedPercent(used, used + available);
        double inodePercent = node.path("inode_used_percent").asDouble(-1); //$NON-NLS-1$
        if (inodePercent > spacePercent) {
            detail.append(" (inode 기준 판정)"); //$NON-NLS-1$
        }
        return AuditStorageUsage.leveled(target, path, used, used + available,
                Math.max(spacePercent, inodePercent), node.path("device").asText(""), //$NON-NLS-1$ //$NON-NLS-2$
                thresholds, detail.toString());
    }

    private static AuditStorageUsage wal(JsonNode node) {
        String path = node.path("path").asText(""); //$NON-NLS-1$ //$NON-NLS-2$
        if (node.path("expected").asBoolean(false)) { //$NON-NLS-1$
            return AuditStorageUsage.unavailable(Target.WAL, path, node.path("error").asText("")); //$NON-NLS-1$ //$NON-NLS-2$
        }
        if (node.isMissingNode() || node.has("error")) { //$NON-NLS-1$
            return AuditStorageUsage.unknown(Target.WAL, path,
                    node.path("error").asText("헬퍼가 측정 결과를 보내지 않았습니다.")); //$NON-NLS-1$ //$NON-NLS-2$
        }
        String detail = ""; //$NON-NLS-1$
        if (node.has("max_wal_size_bytes")) { //$NON-NLS-1$
            detail = "max_wal_size " + formatBytes(node.path("max_wal_size_bytes").asLong()); //$NON-NLS-1$ //$NON-NLS-2$
        }
        return AuditStorageUsage.informational(Target.WAL, path, node.path("size_bytes").asLong(), detail); //$NON-NLS-1$
    }

    private static Report failed(String reason, String backupDirectory, String selectedDirectory) {
        List<AuditStorageUsage> usages = new ArrayList<>();
        usages.add(AuditStorageUsage.unknown(Target.DB_FILESYSTEM, "", reason)); //$NON-NLS-1$
        usages.add(AuditStorageUsage.unknown(Target.WAL, "", reason)); //$NON-NLS-1$
        usages.add(AuditStorageUsage.unknown(Target.LOG_FILESYSTEM, "", reason)); //$NON-NLS-1$
        if (isSet(backupDirectory)) {
            usages.add(AuditStorageUsage.unknown(Target.BACKUP_FILESYSTEM, backupDirectory.trim(), reason));
        }
        if (isSet(selectedDirectory)) {
            usages.add(AuditStorageUsage.unknown(Target.SELECTED_BACKUP_FILESYSTEM, selectedDirectory.trim(), reason));
        }
        return new Report(usages, Collections.emptyList());
    }

    private static boolean isSet(String value) {
        return value != null && !value.trim().isEmpty();
    }

    static String formatBytes(long bytes) {
        double value = bytes;
        String[] units = { "B", "KiB", "MiB", "GiB", "TiB", "PiB" }; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$ //$NON-NLS-6$
        int unit = 0;
        while (value >= 1024 && unit < units.length - 1) {
            value /= 1024;
            unit++;
        }
        return unit == 0 ? bytes + " B" : String.format(Locale.ROOT, "%.1f %s", value, units[unit]); //$NON-NLS-1$ //$NON-NLS-2$
    }
}
