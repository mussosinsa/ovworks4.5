package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.time.ZoneId;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.businessentities.AuditLog;
import org.ovirt.engine.core.common.config.Config;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.dao.AuditLogDao;
import org.ovirt.engine.core.utils.transaction.TransactionSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decides what is done when the scheduled security verification does not pass.
 *
 * <p>The verification run before the engine starts is a gate: a start whose checks fail does not
 * happen. The scheduled run ({@code ovirt-engine-security-audit.timer}) checks an engine that is
 * already serving, and until now its failure was only recorded - the engine carried on as if the
 * host had passed. {@code ENGINE_SECURITY_VERIFICATION_FAILURE_ACTION} now says what follows:</p>
 *
 * <ul>
 * <li>{@code STOP} (the default, and what anything not named here means): the failure is recorded,
 * the alert {@link AuditLogType#SECURITY_VERIFICATION_SCHEDULED_FAILED} is raised, the halt is
 * recorded as {@link AuditLogType#SECURITY_VERIFICATION_SERVICE_HALTED}, and once
 * {@code ENGINE_SECURITY_VERIFICATION_HALT_DELAY_SECONDS} have passed - time for the event notifier
 * to send the alert while the engine is still there to have written it - the engine service is
 * stopped.</li>
 * <li>{@code NOTIFY}: the failure is recorded and the alert raised; the engine keeps running.</li>
 * </ul>
 *
 * <p>The integrity verification run when the engine starts is answered the same way: it runs
 * once the engine is up, so a failure found then is found on a running engine.</p>
 *
 * <p>A run started from the administration portal ("자체 보안 검증 실행", "무결성 검사 실행") is
 * answered the same way: it checks the same running engine, and a failure found by pressing a
 * button is no less a failure than one found by the timer.</p>
 *
 * <p>The engine runs as an unprivileged user and cannot stop its own service. It leaves a request
 * file instead, and {@code ovirt-engine-security-halt.path} starts a root service that waits out
 * the delay and stops the engine. Deleting the file during the delay cancels the stop.</p>
 */
@Singleton
public class ScheduledVerificationFailureResponse {

    private static final Logger log = LoggerFactory.getLogger(ScheduledVerificationFailureResponse.class);

    /** What the systemd service names itself when it runs the verification. */
    static final String TIMER = "timer"; //$NON-NLS-1$

    /** What a run started from the administration portal names itself. */
    static final String WEBADMIN = "webadmin"; //$NON-NLS-1$

    /**
     * What the run at engine start names itself. Responded to for the integrity verification,
     * which runs after the engine has started; the security audit at start is the start's gate,
     * which refuses the start itself.
     */
    static final String ENGINE_START = "engine-start"; //$NON-NLS-1$

    static final String STOP = "STOP"; //$NON-NLS-1$
    static final String NOTIFY = "NOTIFY"; //$NON-NLS-1$

    /** The reason code the halt record carries, for the screen that lists halts. */
    static final String REASON = "SCHEDULED_VERIFICATION_FAILED"; //$NON-NLS-1$

    /** The same, for a run started from the administration portal. */
    static final String REASON_MANUAL = "MANUAL_VERIFICATION_FAILED"; //$NON-NLS-1$

    /** The same, for the integrity verification run when the engine started. */
    static final String REASON_START = "START_VERIFICATION_FAILED"; //$NON-NLS-1$

    static final int DEFAULT_DELAY_SECONDS = 300;
    static final int MAX_DELAY_SECONDS = 3600;

    /** Beyond the longest delay, the time a stop itself may take before its request counts as lost. */
    static final int STALE_MARGIN_SECONDS = 900;

    /** Watched by ovirt-engine-security-halt.path. */
    static final String DEFAULT_REQUEST = "/var/lib/ovirt-engine/security/halt-request.json"; //$NON-NLS-1$

    @Inject
    private AuditLogDao auditLogDao;

    private Path requestPath = Paths.get(DEFAULT_REQUEST);

    /**
     * @param configured what ENGINE_SECURITY_VERIFICATION_FAILURE_ACTION is set to, or null
     * @return the action taken; a misspelt setting must not be able to turn the stop off quietly
     */
    static String action(String configured) {
        return configured != null && NOTIFY.equalsIgnoreCase(configured.trim()) ? NOTIFY : STOP;
    }

    /** @return the delay, kept within 0..{@link #MAX_DELAY_SECONDS} */
    static int delaySeconds(Integer configured) {
        if (configured == null) {
            return DEFAULT_DELAY_SECONDS;
        }
        return Math.max(0, Math.min(MAX_DELAY_SECONDS, configured));
    }

    /**
     * @param ranAt when the failed verification ran
     * @param engineStarted when this engine started
     * @return whether this engine was running when the verification ran, and so is the engine the
     *         verification was about. A failure found while the engine was down is reported when it
     *         next starts, and that start has passed the gate of its own; stopping it then would stop
     *         an engine on the strength of a check made before it existed.
     */
    static boolean ranWhileRunning(Instant ranAt, Instant engineStarted) {
        return ranAt == null || engineStarted == null || !ranAt.isBefore(engineStarted);
    }

    static String requestJson(String check, Instant ranAt, Instant requested, Instant notBefore) {
        return requestJson(REASON, check, ranAt, requested, notBefore);
    }

    static String requestJson(String reason, String check, Instant ranAt, Instant requested, Instant notBefore) {
        return "{\n" //$NON-NLS-1$
                + "  \"reason\": \"" + reason + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
                + "  \"check\": \"" + check + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
                + "  \"ran_at\": \"" + (ranAt == null ? "" : ranAt.toString()) + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                + "  \"requested_at\": \"" + requested + "\",\n" //$NON-NLS-1$ //$NON-NLS-2$
                + "  \"not_before\": " + notBefore.getEpochSecond() + "\n" //$NON-NLS-1$ //$NON-NLS-2$
                + "}\n"; //$NON-NLS-1$
    }

    /**
     * Responds to a verification result that did not pass.
     *
     * @param check {@code security} or {@code integrity}, which verification failed
     * @param source what ran it; the timer's run and a run from the administration portal are
     *        responded to, a start's own run is the start's gate and is not
     * @param ranAt when it ran
     * @param summary what it found, as the failure record already says it
     */
    public void respond(String check, String source, Instant ranAt, String summary) {
        respond(check, source, ranAt, summary, null);
    }

    /**
     * As {@link #respond(String, String, Instant, String)}, naming who started the run.
     *
     * @return what happens to the engine, in words for the person who pressed the button, or null
     *         when the run is not one this responds to
     */
    public synchronized String respond(String check, String source, Instant ranAt, String summary, String user) {
        if (!respondsTo(check, source)) {
            return null;
        }
        boolean manual = WEBADMIN.equals(source);
        boolean start = ENGINE_START.equals(source);
        String action = action(configString(ConfigValues.ENGINE_SECURITY_VERIFICATION_FAILURE_ACTION));
        int delay = delaySeconds(configInteger(ConfigValues.ENGINE_SECURITY_VERIFICATION_HALT_DELAY_SECONDS));
        String run = start ? describeStartRun(check) : describeRun(check, manual, user);
        String reason = manual ? REASON_MANUAL : start ? REASON_START : REASON;
        String what = run
                + StartupSecurityAuditManager.at(ranAt, ZoneId.systemDefault())
                + " did not pass (" + summary + ")"; //$NON-NLS-1$ //$NON-NLS-2$

        if (!ranWhileRunning(ranAt, engineStarted())) {
            log.warn("엔진 정지 전에 실행된 정기 보안검증 실패를 기동 후 보고함; 엔진은 정지하지 않음; check='{}'", check);
            record(AuditLogType.SECURITY_VERIFICATION_SCHEDULED_FAILED, what
                    + ". It ran while the engine was not running, so the engine that has started since"
                    + " is not stopped; run the verification again to confirm the host");
            return null;
        }
        if (NOTIFY.equals(action)) {
            log.warn("보안검증 실패; 정책 NOTIFY에 따라 엔진은 계속 동작함; check='{}'; source='{}'", check, source);
            record(AuditLogType.SECURITY_VERIFICATION_SCHEDULED_FAILED, what
                    + ". The engine keeps running (ENGINE_SECURITY_VERIFICATION_FAILURE_ACTION=NOTIFY)");
            return "엔진 정지 정책이 NOTIFY이므로 엔진은 계속 동작합니다."; //$NON-NLS-1$
        }
        Instant now = Instant.now();
        if (Files.exists(requestPath)) {
            if (!isStale(requestPath, now)) {
                // A run checks the security audit and the integrity verification apart, and both
                // failing is one reason to stop, not two. A request that was cancelled - the file
                // removed - is no longer pending, and a later failure asks again.
                record(AuditLogType.SECURITY_VERIFICATION_SCHEDULED_FAILED, what
                        + ". The engine is already being stopped (ENGINE_SECURITY_VERIFICATION_FAILURE_ACTION=STOP)");
                return "엔진 정지가 이미 진행 중입니다."; //$NON-NLS-1$
            }
            // Older than any delay the stop could have waited: nothing carried it out, and taking it
            // as pending would leave every later failure answered with a stop that never comes.
            log.warn("이전 엔진 정지 요청이 처리되지 않음; ovirt-engine-security-halt.path 확인 필요; path='{}'",
                    requestPath);
            record(AuditLogType.SECURITY_AUDIT_WARNING,
                    "An earlier engine stop request was never carried out; check that " //$NON-NLS-1$
                            + "ovirt-engine-security-halt.path is enabled: " + requestPath); //$NON-NLS-1$
        }

        Instant notBefore = now.plusSeconds(delay);
        String stopsAt = StartupSecurityAuditManager.at(notBefore, ZoneId.systemDefault());
        // The alert first: it is what the notifier sends, and it has to be in the event list for the
        // whole of the delay for the notifier to find it.
        record(AuditLogType.SECURITY_VERIFICATION_SCHEDULED_FAILED, what
                + ". The engine will be stopped in " + delay + " seconds" + stopsAt
                + " (ENGINE_SECURITY_VERIFICATION_FAILURE_ACTION=STOP)");
        // Recorded before the request is written: with no delay the stop can follow at once, and
        // the record of why must already be there.
        log.error("보안검증 실패로 엔진 정지를 요청함; check='{}'; source='{}'; delaySeconds={}; path='{}'",
                check, source, delay, requestPath);
        record(AuditLogType.SECURITY_VERIFICATION_SERVICE_HALTED,
                "The engine service is being stopped" + stopsAt + " because " //$NON-NLS-1$ //$NON-NLS-2$
                        + Character.toLowerCase(run.charAt(0)) + run.substring(1)
                        + " did not pass. Remove " + requestPath //$NON-NLS-1$
                        + " before then to keep it running", //$NON-NLS-1$
                reason);
        try {
            writeRequest(requestJson(reason, check, ranAt, now, notBefore));
        } catch (IOException | RuntimeException e) {
            log.error("엔진 정지 요청을 기록하지 못함; path='{}'; error='{}'", requestPath, e.getMessage());
            record(AuditLogType.SECURITY_AUDIT_FAILED,
                    "The engine was NOT stopped after " //$NON-NLS-1$
                            + Character.toLowerCase(run.charAt(0)) + run.substring(1)
                            + " failed: the stop request could not be written to " //$NON-NLS-1$
                            + requestPath + ": " + e.getMessage()); //$NON-NLS-1$
            return "엔진 정지 요청을 기록하지 못했습니다: " + e.getMessage(); //$NON-NLS-1$
        }
        return haltNotice(delay, stopsAt, requestPath);
    }

    /** What the person who pressed the button is told: when the engine stops, and how to keep it. */
    static String haltNotice(int delay, String stopsAt, Path request) {
        String when = stopsAt.startsWith(" at ") ? "(" + stopsAt.substring(4) + ")" : ""; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        return "엔진이 " + delay + "초 후" + when + " 정지됩니다. 취소하려면 그 전에 " //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                + request + " 파일을 삭제하십시오."; //$NON-NLS-1$
    }

    /** "The scheduled security verification", or the run from the portal and who started it. */
    static String describeRun(String check, boolean manual, String user) {
        if (!manual) {
            return "The scheduled " + check + " verification"; //$NON-NLS-1$ //$NON-NLS-2$
        }
        return "The " + check + " verification run from the administration portal" //$NON-NLS-1$ //$NON-NLS-2$
                + (user == null || user.isEmpty() ? "" : " by " + user); //$NON-NLS-1$ //$NON-NLS-2$
    }

    /**
     * @return whether a failure of this run is responded to: the timer's and the portal's, of
     *         either check, and the integrity verification run at engine start. The security
     *         audit at start is not: it is the start's gate, and a start it fails does not happen.
     */
    static boolean respondsTo(String check, String source) {
        return TIMER.equals(source)
                || WEBADMIN.equals(source)
                || ENGINE_START.equals(source) && IntegrityVerificationAuditManager.KIND.equals(check);
    }

    /** "The integrity verification run when the engine started". */
    static String describeStartRun(String check) {
        return "The " + check + " verification run when the engine started"; //$NON-NLS-1$ //$NON-NLS-2$
    }

    /** @return whether a request has outlived the longest wait the stop could have taken */
    static boolean isStale(Path request, Instant now) {
        try {
            Instant written = Files.getLastModifiedTime(request).toInstant();
            return written.isBefore(now.minusSeconds(MAX_DELAY_SECONDS + STALE_MARGIN_SECONDS));
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Written beside and then moved into place, so that the path unit never starts its service on
     * half a file.
     */
    private void writeRequest(String json) throws IOException {
        Path dir = requestPath.getParent();
        Files.createDirectories(dir);
        Path partial = dir.resolve("." + requestPath.getFileName() + ".partial"); //$NON-NLS-1$ //$NON-NLS-2$
        Files.write(partial, json.getBytes(StandardCharsets.UTF_8));
        try {
            Files.setPosixFilePermissions(partial, PosixFilePermissions.fromString("rw-------")); //$NON-NLS-1$
        } catch (UnsupportedOperationException e) {
            // Not a POSIX file system; the directory itself is private to the engine.
        }
        Files.move(partial, requestPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static Instant engineStarted() {
        try {
            return Instant.ofEpochMilli(ManagementFactory.getRuntimeMXBean().getStartTime());
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String configString(ConfigValues key) {
        try {
            return Config.<String> getValue(key);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static Integer configInteger(ConfigValues key) {
        try {
            return Config.<Integer> getValue(key);
        } catch (RuntimeException e) {
            return null;
        }
    }

    void setRequestPath(Path requestPath) {
        this.requestPath = requestPath;
    }

    void setAuditLogDao(AuditLogDao auditLogDao) {
        this.auditLogDao = auditLogDao;
    }

    private void record(AuditLogType type, String message) {
        record(type, message, message);
    }

    private void record(AuditLogType type, String message, String customData) {
        AuditLog auditLog = new AuditLog(type, type.getSeverity());
        auditLog.setMessage(message);
        auditLog.setCustomData(customData);
        TransactionSupport.executeInNewTransaction(() -> {
            auditLogDao.save(auditLog);
            return null;
        });
    }
}
