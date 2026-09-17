package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * What the AIDE integrity verification found, read back from what it left behind.
 *
 * <p>Kept apart from {@link SecurityAuditRunner} on purpose. The security audit and the integrity
 * verification are two checks answering two questions - whether the installation is configured
 * securely, and whether its files are still the files that were installed - and the audit log
 * records them apart. Reading them through one class would have one run's result standing in for
 * the other's the moment either is missing.</p>
 */
public final class IntegrityVerification {

    private static final Logger log = LoggerFactory.getLogger(IntegrityVerification.class);

    /** Where the runner script leaves the result of the integrity verification. */
    private static final String DEFAULT_RESULTS =
            "/var/lib/ovirt-engine/security/integrity-results.json"; //$NON-NLS-1$

    /** Names the file the runner writes its result to, overriding the default. */
    private static final String RESULTS_ENV = "INTEGRITY_VERIFICATION_RESULTS"; //$NON-NLS-1$

    private IntegrityVerification() {
    }

    /** What one run of the integrity verification produced. */
    public static final class Result {
        private final Instant timestamp;
        private final String status;
        private final int exitCode;
        private final String source;
        private final Path logFile;

        Result(Instant timestamp, String status, int exitCode, String source, Path logFile) {
            this.timestamp = timestamp;
            this.status = status;
            this.exitCode = exitCode;
            this.source = source;
            this.logFile = logFile;
        }

        /** When the verification ran, or null when it did not say. */
        public Instant getTimestamp() {
            return timestamp;
        }

        /** {@code PASS} when nothing changed, {@code FAIL} when something did, {@code ERROR}. */
        public String getStatus() {
            return status;
        }

        /** AIDE's own exit code, or the runner's when AIDE never ran. */
        public int getExitCode() {
            return exitCode;
        }

        /** What asked for the verification: {@code timer}, {@code webadmin}, {@code engine-start}. */
        public String getSource() {
            return source;
        }

        /** The AIDE report this run wrote, or null when it did not say. */
        public Path getLogFile() {
            return logFile;
        }

        /** Nothing had changed. */
        public boolean isPassed() {
            return "PASS".equals(status); //$NON-NLS-1$
        }

        /** AIDE could not carry out the check, which is not the same as finding nothing. */
        public boolean isError() {
            return "ERROR".equals(status); //$NON-NLS-1$
        }
    }

    /** One file AIDE reported on. */
    public static final class Change {

        /** What AIDE says happened to the file. */
        public enum Kind {
            /** A file that is there now and was not in the database. */
            ADDED,
            /** A file that was in the database and is not there now. */
            REMOVED,
            /** A file whose recorded attributes no longer match. */
            CHANGED
        }

        private final Kind kind;
        private final String path;

        Change(Kind kind, String path) {
            this.kind = kind;
            this.path = path;
        }

        public Kind getKind() {
            return kind;
        }

        public String getPath() {
            return path;
        }

        /** What goes in the audit log, naming the file and what happened to it. */
        public String describe() {
            switch (kind) {
                case ADDED:
                    return "A file that is not in the integrity database was found: " + path; //$NON-NLS-1$
                case REMOVED:
                    return "A file recorded in the integrity database is missing: " + path; //$NON-NLS-1$
                default:
                    return "A file no longer matches the integrity database: " + path; //$NON-NLS-1$
            }
        }
    }

    /**
     * The headings AIDE prints above each list of files.
     *
     * <p>AIDE 0.16 writes "Added files", 0.17 writes "Added entries", and the same words with a
     * count after them are the summary rather than a heading - hence the end of line.</p>
     */
    private static final Pattern SECTION =
            Pattern.compile("^(Added|Removed|Changed)\\s+(?:files|entries)\\s*:\\s*$");

    /** {@code f++++++++++++++++: /etc/foo}, and 0.16's {@code added: /etc/foo}. */
    private static final Pattern ENTRY = Pattern.compile("^\\S[^:]*:\\s+(/\\S.*)$");

    /** 0.16 names what happened on the line itself, so the heading is not needed to read it. */
    private static final Pattern LABELLED_ENTRY =
            Pattern.compile("^(added|removed|changed)\\s*:\\s+(/\\S.*)$");

    /**
     * Any other heading AIDE prints, which ends the list of files that was being read.
     *
     * <p>"Detailed information about changes:" follows the lists and names each changed file
     * again, one attribute at a time. Read as part of the list above it, every one of those
     * files would be reported twice.</p>
     */
    private static final Pattern OTHER_HEADING = Pattern.compile("^[A-Z][^/]*:\\s*$");

    /** @return where the runner leaves the result, for a caller that has to name the file */
    public static String getResultsPath() {
        String configured = System.getenv(RESULTS_ENV);
        return configured == null || configured.isEmpty() ? DEFAULT_RESULTS : configured;
    }

    /** @return what the verification that last ran left behind, or empty when it left nothing */
    public static Optional<Result> readResult() {
        Path results = Paths.get(getResultsPath());
        if (!Files.isReadable(results)) {
            return Optional.empty();
        }
        try {
            JsonNode root = new ObjectMapper().readTree(results.toFile());
            String status = root.path("status").asText(""); //$NON-NLS-1$ //$NON-NLS-2$
            if (status.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(new Result(
                    parseTimestamp(root.path("timestamp").asText(null)), //$NON-NLS-1$
                    status,
                    root.path("exit_code").asInt(), //$NON-NLS-1$
                    root.path("source").asText(""), //$NON-NLS-1$ //$NON-NLS-2$
                    parseLogFile(root.path("log_file").asText(null)))); //$NON-NLS-1$
        } catch (IOException | RuntimeException e) {
            log.warn("Unable to read the integrity verification result from {}: {}", //$NON-NLS-1$
                    getResultsPath(), e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Reads which files AIDE reported out of the report it wrote.
     *
     * @return the files it named, or an empty list when the report is missing or names none
     */
    public static List<Change> changesInLog(Path report) {
        if (report == null || !Files.isReadable(report)) {
            return new ArrayList<>();
        }
        try {
            return changesIn(String.join("\n", Files.readAllLines(report, StandardCharsets.UTF_8))); //$NON-NLS-1$
        } catch (IOException | RuntimeException e) {
            log.warn("Unable to read the integrity verification report {}: {}", report, e.getMessage()); //$NON-NLS-1$
            return new ArrayList<>();
        }
    }

    /**
     * Reads which files AIDE reported out of what it printed.
     *
     * <p>AIDE lists the files under a heading per kind, and older versions name the kind on each
     * line instead. Both are read, because which AIDE the host has is not this code's to choose,
     * and a report read as nothing found is indistinguishable from a host that was not touched.</p>
     */
    public static List<Change> changesIn(String report) {
        List<Change> changes = new ArrayList<>();
        if (report == null) {
            return changes;
        }
        Change.Kind section = null;
        for (String line : report.split("\n")) { //$NON-NLS-1$
            String text = line.trim();
            Matcher labelled = LABELLED_ENTRY.matcher(text);
            if (labelled.matches()) {
                changes.add(new Change(kindOf(labelled.group(1)), labelled.group(2).trim()));
                continue;
            }
            Matcher heading = SECTION.matcher(text);
            if (heading.matches()) {
                section = kindOf(heading.group(1));
                continue;
            }
            if (OTHER_HEADING.matcher(text).matches()) {
                section = null;
                continue;
            }
            if (section == null) {
                continue;
            }
            Matcher entry = ENTRY.matcher(text);
            if (entry.matches()) {
                changes.add(new Change(section, entry.group(1).trim()));
            }
        }
        return changes;
    }

    private static Change.Kind kindOf(String word) {
        switch (word.toLowerCase()) {
            case "added": //$NON-NLS-1$
                return Change.Kind.ADDED;
            case "removed": //$NON-NLS-1$
                return Change.Kind.REMOVED;
            default:
                return Change.Kind.CHANGED;
        }
    }

    private static Instant parseTimestamp(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            log.warn("Unable to read the time of the integrity verification from '{}'", value); //$NON-NLS-1$
            return null;
        }
    }

    private static Path parseLogFile(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return Paths.get(value);
        } catch (RuntimeException e) {
            log.warn("Unable to read the integrity verification report path from '{}'", value); //$NON-NLS-1$
            return null;
        }
    }
}
