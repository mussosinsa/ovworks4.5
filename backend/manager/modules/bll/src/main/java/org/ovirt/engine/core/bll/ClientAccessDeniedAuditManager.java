package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.enterprise.concurrent.ManagedScheduledExecutorService;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.BackendService;
import org.ovirt.engine.core.common.businessentities.AuditLog;
import org.ovirt.engine.core.dao.AuditLogDao;
import org.ovirt.engine.core.utils.threadpool.ThreadPools;
import org.ovirt.engine.core.utils.transaction.TransactionSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Puts an attempt from an unregistered address into the engine's event list.
 *
 * <p>Such an attempt never reaches the engine. The web server refuses it at the {@code Require ip}
 * block that the terminal IP rules write, so nothing in the engine sees the request and the event
 * list said nothing at all about it - the one place an administrator would look to find out that
 * somebody is trying addresses.</p>
 *
 * <p>What the web server writes about each refusal is therefore the only account of it there is.
 * This reads that file as it grows and records what it finds.</p>
 */
@Singleton
public class ClientAccessDeniedAuditManager implements BackendService {

    private static final Logger log = LoggerFactory.getLogger(ClientAccessDeniedAuditManager.class);

    /** Where the web server writes them, see the CustomLog in ovirt-engine-proxy.conf. */
    static final String DENIED_LOG = "/var/log/httpd/ovirt-engine-admin-access-denied-audit.log"; //$NON-NLS-1$

    /** How often the file is read for what has been added to it. */
    private static final long CHECK_INTERVAL_SECONDS = 60;

    /** A moment for the web server to create the file before it is first looked for. */
    private static final long START_DELAY_SECONDS = 60;

    /**
     * How many refusals one pass records.
     *
     * <p>Someone sweeping addresses produces them as fast as the network allows, and every one of
     * them in the event list would bury everything else in it. The rest are counted in one closing
     * record and stay in the web server's own log, which is not being emptied.</p>
     */
    private static final int MAX_REPORTED_PER_PASS = 20;

    @Inject
    @ThreadPools(ThreadPools.ThreadPoolType.EngineScheduledThreadPool)
    private ManagedScheduledExecutorService executor;

    @Inject
    private AuditLogDao auditLogDao;

    /** How far into the file has been read. Lines before this were recorded already. */
    private long offset;

    /** Set once the file has been reported unreadable, so it is reported once and not every pass. */
    private boolean reportedUnreadable;

    @PostConstruct
    private void init() {
        log.info("Start initializing {}", getClass().getSimpleName());
        executor.scheduleWithFixedDelay(this::recordNewDenials,
                START_DELAY_SECONDS,
                CHECK_INTERVAL_SECONDS,
                TimeUnit.SECONDS);
        log.info("Finished initializing {}", getClass().getSimpleName());
    }

    void recordNewDenials() {
        try {
            Path deniedLog = Paths.get(DENIED_LOG);
            if (!Files.isReadable(deniedLog)) {
                reportUnreadable(deniedLog);
                return;
            }
            reportedUnreadable = false;
            report(readNewLines(deniedLog));
        } catch (Throwable t) {
            // The next pass reads the same file from the same place; a pass that failed loses
            // nothing and must not take the scheduled task down with it.
            log.error("Exception in reading denied client accesses: {}", ExceptionUtils.getRootCauseMessage(t));
            log.debug("Exception", t);
        }
    }

    /**
     * Reads what has been added since the last pass.
     *
     * <p>A file shorter than where reading last stopped has been rotated or emptied, so reading
     * starts again from the beginning of what is now there rather than from a position in a file
     * that no longer exists.</p>
     */
    private List<String> readNewLines(Path deniedLog) throws IOException {
        List<String> lines = new ArrayList<>();
        try (RandomAccessFile file = new RandomAccessFile(deniedLog.toFile(), "r")) { //$NON-NLS-1$
            if (file.length() < offset) {
                log.info("사용 로그가 교체됨; 처음부터 다시 읽음; path='{}'", DENIED_LOG);
                offset = 0;
            }
            file.seek(offset);
            String line;
            while ((line = file.readLine()) != null) {
                // readLine reads bytes as latin-1; the log is UTF-8 and a user agent can carry
                // anything, so the bytes are put back together and read as what they are.
                lines.add(new String(line.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8));
            }
            offset = file.getFilePointer();
        }
        return lines;
    }

    private void report(List<String> lines) {
        int recorded = 0;
        int denials = 0;
        for (String line : lines) {
            ClientAccessDeniedLog.Denial denial = ClientAccessDeniedLog.parse(line).orElse(null);
            if (denial == null) {
                continue;
            }
            denials++;
            if (recorded < MAX_REPORTED_PER_PASS) {
                log.warn("미등록 주소 접속 거부; address='{}'; request='{}'", denial.getAddress(), denial.getRequest());
                logAuditEvent(AuditLogType.CLIENT_ACCESS_DENIED_UNREGISTERED_ADDRESS, denial.describe());
                recorded++;
            }
        }
        if (denials > recorded) {
            logAuditEvent(AuditLogType.CLIENT_ACCESS_DENIED_UNREGISTERED_ADDRESS,
                    "Access to the engine was denied to unregistered addresses " + (denials - recorded)
                            + " further times; see " + DENIED_LOG);
        }
    }

    /**
     * Says, once, that the file cannot be read.
     *
     * <p>Unreadable means attempts from unregistered addresses are not reaching the event list,
     * which is worth knowing and is not visible in any other way - the event list would simply
     * stay empty, which is what it looks like when nobody is trying. Said once rather than every
     * pass, because a file that is unreadable now is unreadable in a minute too.</p>
     */
    private void reportUnreadable(Path deniedLog) {
        if (reportedUnreadable) {
            return;
        }
        reportedUnreadable = true;
        String detail = Files.exists(deniedLog)
                ? "it cannot be read by the engine" //$NON-NLS-1$
                : "it does not exist yet"; //$NON-NLS-1$
        log.warn("미등록 주소 접속 거부 기록을 읽을 수 없음; path='{}'; 사유='{}'", DENIED_LOG, detail);
        logAuditEvent(AuditLogType.CLIENT_ACCESS_DENIED_UNREGISTERED_ADDRESS,
                "Attempts from unregistered addresses are not being reported: " + DENIED_LOG + " - " + detail);
    }

    private void logAuditEvent(AuditLogType type, String message) {
        AuditLog auditLog = new AuditLog(type, type.getSeverity());
        auditLog.setMessage(message);
        auditLog.setCustomData(message);
        TransactionSupport.executeInNewTransaction(() -> {
            auditLogDao.save(auditLog);
            return null;
        });
    }
}
