package org.ovirt.engine.core.bll;

import java.io.File;
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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Runs the security verification script and reports what it said.
 *
 * <p>Two things ask for the audit - an administrator from the WebAdmin screen, and the engine
 * itself when it starts - and they must not run it at the same time or read its result in two
 * different ways, so both come through here.</p>
 */
public class SecurityAuditRunner {

    private static final Logger log = LoggerFactory.getLogger(SecurityAuditRunner.class);

    static final String RUNNER =
            "/usr/share/ovirt-engine/bin/ovirt-engine-security-verification-runner.sh"; //$NON-NLS-1$

    /**
     * Where ov-works-security_audit.sh leaves the counts of what it checked.
     *
     * <p>Not under /tmp. That directory is world-writable, so a local user can pre-create the
     * path or replace the file between the audit writing it and this reading it, and what then
     * reaches the event list as an audit result is whatever they wrote.</p>
     */
    private static final String DEFAULT_RESULTS =
            "/var/lib/ovirt-engine/security/audit-results.json"; //$NON-NLS-1$

    /**
     * What a start the verification gate refused was refused for.
     *
     * <p>Written by ovirt-engine.py, which refuses the start. A refused start leaves no engine
     * to record anything, so without this a failed verification never reaches the event list at
     * all - the only sign of it is that the engine did not come up.</p>
     */
    private static final String DEFAULT_BLOCKED_START =
            "/var/lib/ovirt-engine/security/last-failed-start.json"; //$NON-NLS-1$

    /**
     * Names the file the audit writes its result to, overriding the default.
     *
     * <p>The audit script and the runner script read the same variable with the same default.
     * Reading it here too keeps the three from disagreeing about where the result is, which
     * looks from this side exactly like an audit that reported nothing.</p>
     */
    private static final String RESULTS_ENV = "SECURITY_AUDIT_RESULTS"; //$NON-NLS-1$

    static final long TIMEOUT_MINUTES = 11;

    /**
     * Held for as long as an audit is running here.
     *
     * <p>The script takes a lock of its own and refuses a second run outright, which reaches the
     * caller as a bare exit code. Holding the answer on this side as well lets each caller say
     * what it wants to say about an audit that is already under way.</p>
     */
    private static final AtomicBoolean RUNNING = new AtomicBoolean();

    /** What the runner script reports through its exit code. */
    public enum Outcome {
        /** Every check passed. */
        PASSED,
        /** The audit ran and found something. This is a result, not a failure to audit. */
        FINDINGS,
        /** An audit was already running, so this one did not start. */
        BUSY,
        /** The audit did not finish in time and was stopped. */
        TIMED_OUT,
        /** The audit could not be run, or did not report a result. */
        FAILED
    }

    /** What one run of the audit produced. */
    public static final class Run {
        private final Outcome outcome;
        private final int exitCode;
        private final String output;

        Run(Outcome outcome, int exitCode, String output) {
            this.outcome = outcome;
            this.exitCode = exitCode;
            this.output = output;
        }

        public Outcome getOutcome() {
            return outcome;
        }

        public int getExitCode() {
            return exitCode;
        }

        /** Everything the script printed, or an empty string when it printed nothing. */
        public String getOutput() {
            return output;
        }
    }

    /**
     * What the audit script left behind after it ran: when it ran, whether it passed, the tally,
     * and where it wrote the detail.
     */
    public static final class Result {
        private final Instant timestamp;
        private final String status;
        private final String source;
        private final Summary summary;
        private final Path logFile;

        Result(Instant timestamp, String status, String source, Summary summary, Path logFile) {
            this.timestamp = timestamp;
            this.status = status;
            this.source = source;
            this.summary = summary;
            this.logFile = logFile;
        }

        /**
         * What asked for the audit: {@code engine-start}, {@code timer} or {@code webadmin}.
         *
         * <p>Read so that a scheduled run is not reported as the one the engine started with,
         * and so that a run from the screen, which reports itself as it goes, is not reported a
         * second time by whoever is watching the result file.</p>
         */
        public String getSource() {
            return source;
        }

        /** When the audit ran, or null when it did not say. */
        public Instant getTimestamp() {
            return timestamp;
        }

        /** {@code PASS} when nothing failed, {@code FAIL} when something did. */
        public String getStatus() {
            return status;
        }

        public Summary getSummary() {
            return summary;
        }

        /** The log the audit wrote its checks to, or null when it did not say. */
        public Path getLogFile() {
            return logFile;
        }

        public boolean isPassed() {
            return "PASS".equals(status); //$NON-NLS-1$
        }
    }

    /** The tally the audit script writes down: how many checks passed, warned and failed. */
    public static final class Summary {
        private final int passed;
        private final int warnings;
        private final int failed;

        Summary(int passed, int warnings, int failed) {
            this.passed = passed;
            this.warnings = warnings;
            this.failed = failed;
        }

        public int getPassed() {
            return passed;
        }

        public int getWarnings() {
            return warnings;
        }

        public int getFailed() {
            return failed;
        }

        @Override
        public String toString() {
            return String.format("passed=%d, warnings=%d, failed=%d", passed, warnings, failed); //$NON-NLS-1$
        }
    }

    /**
     * A start the verification gate refused, as ovirt-engine.py recorded it.
     *
     * <p>The gate runs before the Java daemon, and a start it refuses produces no engine at
     * all. Nothing writes to the event list, so the refusal is only in the systemd journal and
     * in engine.log - and the event list, where an administrator looks, stays empty, which is
     * what it also looks like when every verification passed. This is read at the next start
     * that does succeed so that the refusal is said once, late, rather than never.</p>
     */
    public static final class BlockedStart {

        /** Why the start was refused. The gate writes one of these. */
        static final String CHECKS_FAILED = "SECURITY_CHECKS_FAILED"; //$NON-NLS-1$
        static final String BUSY = "VERIFICATION_BUSY"; //$NON-NLS-1$
        static final String RUNNER_MISSING = "RUNNER_MISSING"; //$NON-NLS-1$
        static final String ERROR = "VERIFICATION_ERROR"; //$NON-NLS-1$

        private final Instant timestamp;
        private final String reason;
        private final String detail;
        private final Summary summary;

        BlockedStart(Instant timestamp, String reason, String detail, Summary summary) {
            this.timestamp = timestamp;
            this.reason = reason;
            this.detail = detail;
            this.summary = summary;
        }

        /** When the start was refused, or null when the record did not say. */
        public Instant getTimestamp() {
            return timestamp;
        }

        public String getReason() {
            return reason;
        }

        /** The tally of the audit that refused the start, or null when it never ran. */
        public Summary getSummary() {
            return summary;
        }

        /**
         * What goes in the event list.
         *
         * <p>Written from the reason rather than from the gate's own wording, so that the event
         * list reads in one language and one voice; the gate's wording is in engine.log beside
         * the rest of what it printed.</p>
         */
        public String describe(String when) {
            StringBuilder message = new StringBuilder("The engine was prevented from starting"); //$NON-NLS-1$
            // Before the reason, not after it: several of the reasons end in a clause of their
            // own, and a time hung off the end of one of those reads as part of it.
            message.append(when == null ? "" : when); //$NON-NLS-1$
            message.append(because());
            if (summary != null) {
                message.append("; ").append(summary); //$NON-NLS-1$
            }
            return message.toString();
        }

        /** What goes in the event list when the record did not say when the start was refused. */
        public String describe() {
            return describe(""); //$NON-NLS-1$
        }

        private String because() {
            switch (reason == null ? "" : reason) { //$NON-NLS-1$
                case CHECKS_FAILED:
                    return " because the security verification reported failed checks"; //$NON-NLS-1$
                case BUSY:
                    return " because another security verification was still running," //$NON-NLS-1$
                            + " so the start could not be verified"; //$NON-NLS-1$
                case RUNNER_MISSING:
                    return " because the security verification could not be run: " + RUNNER; //$NON-NLS-1$
                case ERROR:
                    return " because the security verification could not be completed"; //$NON-NLS-1$
                default:
                    return detail == null || detail.isEmpty()
                            ? " by the security verification" //$NON-NLS-1$
                            : " by the security verification: " + detail; //$NON-NLS-1$
            }
        }
    }

    /**
     * One check the audit reported on, as the audit script prints it.
     *
     * <p>The tally says how many checks failed; this says which. It is what an operator reading
     * the event list needs, and it is otherwise only in a log file on the engine host.</p>
     */
    public static final class Finding {

        /** How the audit script marked the line. */
        public enum Level {
            FAILED,
            WARNING
        }

        private final Level level;
        private final String text;

        Finding(Level level, String text) {
            this.level = level;
            this.text = text;
        }

        public Level getLevel() {
            return level;
        }

        /** What the check reported, without the marker the script prints in front of it. */
        public String getText() {
            return text;
        }
    }

    /** {@code [FAIL] something is wrong}, as log_fail and log_warn in the audit script print it. */
    private static final Pattern FINDING_LINE = Pattern.compile("^\\[(FAIL|WARN)\\]\\s*(.+)$");

    /** Colour the script emits when it thinks it is talking to a terminal. */
    private static final Pattern ANSI_ESCAPE = Pattern.compile("\\u001B\\[[0-9;]*m");

    /**
     * Reads the checks that did not pass out of what the audit printed.
     *
     * <p>Only the failures and the warnings are picked out. A run reports dozens of checks that
     * passed, and an event for each of those would bury the ones that did not.</p>
     */
    public static List<Finding> findingsIn(String output) {
        List<Finding> findings = new ArrayList<>();
        if (output == null) {
            return findings;
        }
        for (String line : output.split("\n")) { //$NON-NLS-1$
            Matcher matcher = FINDING_LINE.matcher(ANSI_ESCAPE.matcher(line).replaceAll("").trim()); //$NON-NLS-1$
            if (matcher.matches()) {
                findings.add(new Finding(
                        "FAIL".equals(matcher.group(1)) ? Finding.Level.FAILED : Finding.Level.WARNING, //$NON-NLS-1$
                        matcher.group(2).trim()));
            }
        }
        return findings;
    }

    /** Exit codes the runner script uses, see ovirt-engine-security-verification-runner.sh. */
    private static final int EXIT_FINDINGS = 20;
    private static final int EXIT_BUSY = 75;

    private SecurityAuditRunner() {
    }

    /** @return whether an audit is running here at this moment */
    public static boolean isRunning() {
        return RUNNING.get();
    }

    /** @return whether the runner script is in place and can be run */
    public static boolean isAvailable() {
        File script = new File(RUNNER);
        return script.exists() && script.canExecute();
    }

    /** @return whether the runner script is there at all, so a caller can say which is wrong */
    public static boolean exists() {
        return new File(RUNNER).exists();
    }

    /**
     * Runs the audit and waits for it.
     *
     * @param mode which checks to run, as the runner script names them
     * @param source what asked for the audit, recorded in the script's own log
     */
    public static Run run(String mode, String source) {
        if (!RUNNING.compareAndSet(false, true)) {
            return new Run(Outcome.BUSY, EXIT_BUSY, ""); //$NON-NLS-1$
        }
        try {
            return execute(mode, source);
        } finally {
            RUNNING.set(false);
        }
    }

    private static Run execute(String mode, String source) {
        Path outputFile = null;
        try {
            outputFile = Files.createTempFile("ovirt-security-audit-", ".log"); //$NON-NLS-1$ //$NON-NLS-2$
            // Run the script itself so its bash shebang is honored. Going through `sh` adds a
            // process and can run a bash-specific script under an incompatible shell.
            ProcessBuilder processBuilder = new ProcessBuilder(RUNNER, mode, source);
            processBuilder.redirectErrorStream(true);
            processBuilder.redirectOutput(outputFile.toFile());
            Process process = processBuilder.start();
            // The audit must never wait for an interactive child command (su, for one) to be
            // given something on the engine's standard input.
            process.getOutputStream().close();

            if (!process.waitFor(TIMEOUT_MINUTES, TimeUnit.MINUTES)) {
                terminateProcessTree(process);
                return new Run(Outcome.TIMED_OUT, -1, readOutput(outputFile));
            }

            int exitCode = process.exitValue();
            return new Run(outcomeOf(exitCode), exitCode, readOutput(outputFile));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while running the security audit", e); //$NON-NLS-1$
            return new Run(Outcome.FAILED, -1, ""); //$NON-NLS-1$
        } catch (Exception e) {
            log.error("Failed to execute the security audit script", e); //$NON-NLS-1$
            return new Run(Outcome.FAILED, -1, e.getMessage() == null ? "" : e.getMessage()); //$NON-NLS-1$
        } finally {
            deleteQuietly(outputFile);
        }
    }

    /** Reads the runner script's exit code, whose values are fixed by that script. */
    static Outcome outcomeOf(int exitCode) {
        switch (exitCode) {
            case 0:
                return Outcome.PASSED;
            case EXIT_FINDINGS:
                return Outcome.FINDINGS;
            case EXIT_BUSY:
                return Outcome.BUSY;
            default:
                return Outcome.FAILED;
        }
    }

    /** @return where the audit script leaves its result, for a caller that has to name the file */
    public static String getResultsPath() {
        String configured = System.getenv(RESULTS_ENV);
        return configured == null || configured.isEmpty() ? DEFAULT_RESULTS : configured;
    }

    /**
     * @return what the audit that last ran left behind, or empty when it left nothing readable -
     *         which is every audit that could not be run, and an integrity-only run
     */
    public static Optional<Result> readResult() {
        Path results = Paths.get(getResultsPath());
        if (!Files.isReadable(results)) {
            return Optional.empty();
        }
        try {
            JsonNode root = new ObjectMapper().readTree(results.toFile());
            JsonNode summary = root.path("summary"); //$NON-NLS-1$
            if (summary.isMissingNode()) {
                return Optional.empty();
            }
            return Optional.of(new Result(
                    parseTimestamp(root.path("timestamp").asText(null)), //$NON-NLS-1$
                    root.path("status").asText(""), //$NON-NLS-1$ //$NON-NLS-2$
                    root.path("source").asText(""), //$NON-NLS-1$ //$NON-NLS-2$
                    new Summary(
                            summary.path("passed").asInt(), //$NON-NLS-1$
                            summary.path("warnings").asInt(), //$NON-NLS-1$
                            summary.path("failed").asInt()), //$NON-NLS-1$
                    parseLogFile(root.path("log_file").asText(null)))); //$NON-NLS-1$
        } catch (IOException | RuntimeException e) {
            log.warn("Unable to read the security audit results from {}: {}", //$NON-NLS-1$
                    getResultsPath(), e.getMessage());
            return Optional.empty();
        }
    }

    private static Instant parseTimestamp(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            log.warn("Unable to read the time of the security audit from '{}'", value); //$NON-NLS-1$
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
            log.warn("Unable to read the security audit log path from '{}'", value); //$NON-NLS-1$
            return null;
        }
    }

    /** @return where the gate records a start it refused, for a caller that has to name it */
    public static String getBlockedStartPath() {
        return DEFAULT_BLOCKED_START;
    }

    /**
     * @return the start the verification gate last refused, or empty when it refused none since
     *         the last one was reported
     */
    public static Optional<BlockedStart> readBlockedStart() {
        Path record = Paths.get(DEFAULT_BLOCKED_START);
        if (!Files.isReadable(record)) {
            return Optional.empty();
        }
        try {
            JsonNode root = new ObjectMapper().readTree(record.toFile());
            JsonNode summary = root.path("results").path("summary"); //$NON-NLS-1$ //$NON-NLS-2$
            return Optional.of(new BlockedStart(
                    parseTimestamp(root.path("timestamp").asText(null)), //$NON-NLS-1$
                    root.path("reason").asText(""), //$NON-NLS-1$ //$NON-NLS-2$
                    root.path("detail").asText(""), //$NON-NLS-1$ //$NON-NLS-2$
                    summary.isMissingNode() || summary.isNull() ? null : new Summary(
                            summary.path("passed").asInt(), //$NON-NLS-1$
                            summary.path("warnings").asInt(), //$NON-NLS-1$
                            summary.path("failed").asInt()))); //$NON-NLS-1$
        } catch (IOException | RuntimeException e) {
            log.warn("Unable to read the blocked start record from {}: {}", //$NON-NLS-1$
                    DEFAULT_BLOCKED_START, e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Forgets a refused start once it has been reported.
     *
     * @return whether it is gone; a record that cannot be removed would be reported again at
     *         every start, which the caller has to know about to say so once
     */
    public static boolean clearBlockedStart() {
        try {
            Files.deleteIfExists(Paths.get(DEFAULT_BLOCKED_START));
            return true;
        } catch (IOException | RuntimeException e) {
            log.warn("Unable to remove the blocked start record {}: {}", //$NON-NLS-1$
                    DEFAULT_BLOCKED_START, e.getMessage());
            return false;
        }
    }

    /**
     * Reads the checks that did not pass out of the log the audit wrote them to.
     *
     * @return the findings, or an empty list when the log is missing or cannot be read
     */
    public static List<Finding> findingsInLog(Path auditLog) {
        if (auditLog == null || !Files.isReadable(auditLog)) {
            return new ArrayList<>();
        }
        try {
            return findingsIn(String.join("\n", Files.readAllLines(auditLog, StandardCharsets.UTF_8))); //$NON-NLS-1$
        } catch (IOException | RuntimeException e) {
            log.warn("Unable to read the security audit log {}: {}", auditLog, e.getMessage()); //$NON-NLS-1$
            return new ArrayList<>();
        }
    }

    private static String readOutput(Path outputFile) {
        if (outputFile == null) {
            return ""; //$NON-NLS-1$
        }
        try {
            return String.join("\n", Files.readAllLines(outputFile, StandardCharsets.UTF_8)); //$NON-NLS-1$
        } catch (IOException e) {
            log.warn("Unable to read the security audit output: {}", e.getMessage()); //$NON-NLS-1$
            return ""; //$NON-NLS-1$
        }
    }

    private static void deleteQuietly(Path path) {
        if (path == null) {
            return;
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            log.warn("Unable to remove the security audit output file {}: {}", path, e.getMessage()); //$NON-NLS-1$
        }
    }

    private static void terminateProcessTree(Process process) throws InterruptedException {
        // A shell script makes children of its own. Destroying the shell alone leaves them
        // running, and the action that started them never finishes.
        process.toHandle().descendants().forEach(ProcessHandle::destroy);
        process.destroy();
        if (!process.waitFor(5, TimeUnit.SECONDS)) {
            process.toHandle().descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
            process.waitFor();
        }
    }
}
