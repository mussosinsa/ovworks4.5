package org.ovirt.engine.core.bll;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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

    /** Where ov-works-security_audit.sh leaves the counts of what it checked. */
    private static final String RESULTS = "/tmp/ovirt-security-audit-results.json"; //$NON-NLS-1$

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

    /**
     * @return the tally of the audit that last ran, or empty when it left none - which is every
     *         audit that could not be run, and an integrity-only run
     */
    public static Optional<Summary> readSummary() {
        Path results = Paths.get(RESULTS);
        if (!Files.isReadable(results)) {
            return Optional.empty();
        }
        try {
            JsonNode summary = new ObjectMapper().readTree(results.toFile()).path("summary"); //$NON-NLS-1$
            if (summary.isMissingNode()) {
                return Optional.empty();
            }
            return Optional.of(new Summary(
                    summary.path("passed").asInt(), //$NON-NLS-1$
                    summary.path("warnings").asInt(), //$NON-NLS-1$
                    summary.path("failed").asInt())); //$NON-NLS-1$
        } catch (IOException | RuntimeException e) {
            log.warn("Unable to read the security audit results from {}: {}", RESULTS, e.getMessage()); //$NON-NLS-1$
            return Optional.empty();
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
