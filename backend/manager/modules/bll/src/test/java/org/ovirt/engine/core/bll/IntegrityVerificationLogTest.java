package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

/**
 * AIDE's report is the only account of which files no longer match, so a report read as naming
 * nothing is indistinguishable from a host nobody touched.
 */
class IntegrityVerificationLogTest {

    /** AIDE 0.17 and later: a heading per kind, and an attribute mask in front of each path. */
    private static final String AIDE_0_17 = String.join("\n",
            "Start timestamp: 2026-09-17 06:51:40 +0900 (AIDE 0.17.4)",
            "AIDE found differences between database and filesystem!!",
            "",
            "Summary:",
            "  Total number of entries:\t123456",
            "  Added entries:\t\t1",
            "  Removed entries:\t\t1",
            "  Changed entries:\t\t1",
            "",
            "---------------------------------------------------",
            "Added entries:",
            "---------------------------------------------------",
            "",
            "f++++++++++++++++: /etc/ovirt-engine/engine.conf.d/99-new.conf",
            "",
            "---------------------------------------------------",
            "Removed entries:",
            "---------------------------------------------------",
            "",
            "f----------------: /usr/share/ovirt-engine/bin/ov-works-security_audit.sh",
            "",
            "---------------------------------------------------",
            "Changed entries:",
            "---------------------------------------------------",
            "",
            "f   ...    .C... : /etc/httpd/conf.d/ssl.conf",
            "",
            "---------------------------------------------------",
            "Detailed information about changes:",
            "---------------------------------------------------",
            "",
            "File: /etc/httpd/conf.d/ssl.conf",
            "  SHA256   : aaaa | bbbb");

    /** AIDE 0.16: the same report, with the kind named on each line instead of above it. */
    private static final String AIDE_0_16 = String.join("\n",
            "AIDE found differences between database and filesystem!!",
            "Start timestamp: 2026-09-17 06:51:40",
            "",
            "Summary:",
            "  Total number of files:\t123456",
            "  Added files:\t\t\t1",
            "  Removed files:\t\t1",
            "  Changed files:\t\t1",
            "",
            "---------------------------------------------------",
            "Added files:",
            "---------------------------------------------------",
            "",
            "added: /etc/ovirt-engine/engine.conf.d/99-new.conf",
            "",
            "---------------------------------------------------",
            "Removed files:",
            "---------------------------------------------------",
            "",
            "removed: /usr/share/ovirt-engine/bin/ov-works-security_audit.sh",
            "",
            "---------------------------------------------------",
            "Changed files:",
            "---------------------------------------------------",
            "",
            "changed: /etc/httpd/conf.d/ssl.conf");

    private static String summarise(List<IntegrityVerification.Change> changes) {
        return changes.stream()
                .map(change -> change.getKind() + " " + change.getPath())
                .collect(Collectors.joining("\n"));
    }

    @Test
    void readsWhatTheAideOnThisHostReported() {
        String expected = String.join("\n",
                "ADDED /etc/ovirt-engine/engine.conf.d/99-new.conf",
                "REMOVED /usr/share/ovirt-engine/bin/ov-works-security_audit.sh",
                "CHANGED /etc/httpd/conf.d/ssl.conf");

        // Which AIDE the host has is not this code's to choose, so both are read.
        assertEquals(expected, summarise(IntegrityVerification.changesIn(AIDE_0_17)));
        assertEquals(expected, summarise(IntegrityVerification.changesIn(AIDE_0_16)));
    }

    @Test
    void doesNotCountAChangedFileTwiceForBeingDescribedTwice() {
        // "Detailed information about changes:" names every changed file again, one attribute at
        // a time. Read as part of the list above it, each of them would be reported twice.
        List<IntegrityVerification.Change> changes = IntegrityVerification.changesIn(AIDE_0_17);

        assertEquals(1, changes.stream()
                .filter(c -> c.getPath().equals("/etc/httpd/conf.d/ssl.conf")).count());
    }

    @Test
    void readsNothingOutOfAReportThatFoundNothing() {
        assertTrue(IntegrityVerification.changesIn(String.join("\n",
                "Start timestamp: 2026-09-17 06:51:40 +0900 (AIDE 0.17.4)",
                "AIDE found NO differences between database and filesystem. Looks okay!!",
                "",
                "Summary:",
                "  Total number of entries:\t123456",
                "  Added entries:\t\t0",
                "  Removed entries:\t\t0",
                "  Changed entries:\t\t0")).isEmpty());
        assertTrue(IntegrityVerification.changesIn("").isEmpty());
        assertTrue(IntegrityVerification.changesIn(null).isEmpty());
    }

    @Test
    void saysWhatHappenedToEachFileItNames() {
        List<IntegrityVerification.Change> changes = IntegrityVerification.changesIn(AIDE_0_17);

        assertTrue(changes.get(0).describe().contains("is not in the integrity database"),
                changes.get(0).describe());
        assertTrue(changes.get(1).describe().contains("is missing"), changes.get(1).describe());
        assertTrue(changes.get(2).describe().contains("no longer matches"), changes.get(2).describe());
        for (IntegrityVerification.Change change : changes) {
            assertTrue(change.describe().contains(change.getPath()), change.describe());
        }
    }
}
