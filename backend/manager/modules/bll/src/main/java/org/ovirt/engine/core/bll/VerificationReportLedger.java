package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Remembers which verification results have already reached the audit log.
 *
 * <p>The security audit and the integrity verification each leave one result file, which is
 * replaced by the next run. Whoever reports them reads the file as it finds it, so without this
 * the daily run's result would be reported again at every engine restart until the next day
 * replaced it - a record of one verification standing in the audit log as several.</p>
 *
 * <p>Kept on disk because engine restarts are exactly the occasion this guards against, and in
 * memory as well so that a ledger that cannot be written costs one repeat per restart rather
 * than one per pass.</p>
 */
final class VerificationReportLedger {

    private static final Logger log = LoggerFactory.getLogger(VerificationReportLedger.class);

    private static final String DIR = "/var/lib/ovirt-engine/security"; //$NON-NLS-1$

    private static final Map<String, String> REPORTED = new ConcurrentHashMap<>();

    private VerificationReportLedger() {
    }

    /**
     * @param kind which verification, naming the ledger file
     * @param when the time the result says it ran, or null when it did not say
     * @return whether this result has already been reported
     */
    static boolean alreadyReported(String kind, Instant when) {
        if (when == null) {
            // A result that does not say when it ran cannot be told from the one before it, so
            // it is reported rather than silently dropped; a repeat is the lesser fault.
            return false;
        }
        String reported = REPORTED.get(kind);
        if (reported == null) {
            reported = readLedger(kind);
        }
        return when.toString().equals(reported);
    }

    /** Records that this result has reached the audit log. */
    static void markReported(String kind, Instant when) {
        if (when == null) {
            return;
        }
        REPORTED.put(kind, when.toString());
        Path ledger = ledgerOf(kind);
        try {
            Files.createDirectories(ledger.getParent());
            Files.write(ledger, when.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            // Held in memory either way, so this costs a repeat at the next restart and not a
            // report that never happens.
            log.warn("Unable to record the reported verification in {}: {}", ledger, e.getMessage()); //$NON-NLS-1$
        }
    }

    private static String readLedger(String kind) {
        Path ledger = ledgerOf(kind);
        if (!Files.isReadable(ledger)) {
            return null;
        }
        try {
            return new String(Files.readAllBytes(ledger), StandardCharsets.UTF_8).trim();
        } catch (IOException | RuntimeException e) {
            log.warn("Unable to read the reported verification from {}: {}", ledger, e.getMessage()); //$NON-NLS-1$
            return null;
        }
    }

    private static Path ledgerOf(String kind) {
        return Paths.get(DIR, "reported-" + kind); //$NON-NLS-1$
    }
}
