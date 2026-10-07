package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The files the integrity verification measures, each with the process it belongs to.
 *
 * <p>Read from the verification's own AIDE configuration, which engine-setup writes from the list
 * of the six main processes' files (ovirt_engine_setup/aide.py): a line {@code #@ PROCESS PATH}
 * for every file in the baseline, {@code #- PROCESS PATH} for one that is not, because it was not
 * there when the baseline was taken. With it the audit log records the result of every file of
 * every process - those that matched as well as those that did not - and names the process of
 * each file AIDE reports.</p>
 */
public final class IntegrityTargets {

    private static final Logger log = LoggerFactory.getLogger(IntegrityTargets.class);

    static final String CONFIG = "/etc/ovirt-engine/aide/ovworks-aide.conf"; //$NON-NLS-1$

    /** The process of a file that is not on the list: AIDE reported something it should not. */
    static final String UNLISTED = "목록 외"; //$NON-NLS-1$

    private static final String MEASURED = "#@ "; //$NON-NLS-1$
    private static final String NOT_MEASURED = "#- "; //$NON-NLS-1$

    /** One file of one process. */
    public static final class Target {
        private final String process;
        private final String path;
        private final boolean measured;

        Target(String process, String path, boolean measured) {
            this.process = process;
            this.path = path;
            this.measured = measured;
        }

        public String getProcess() {
            return process;
        }

        public String getPath() {
            return path;
        }

        /** Whether the file is in the baseline; it is not when it was not there at the time. */
        public boolean isMeasured() {
            return measured;
        }

        /** Whether AIDE reporting this path is reporting on this target (a file, or one in it). */
        boolean covers(String reported) {
            return reported.equals(path) || reported.startsWith(path + "/"); //$NON-NLS-1$
        }
    }

    private final List<Target> targets;

    IntegrityTargets(List<Target> targets) {
        this.targets = Collections.unmodifiableList(targets);
    }

    public List<Target> getTargets() {
        return targets;
    }

    /** @return the target AIDE's report of this path is about, or null when it is on no list */
    public Target targetOf(String reported) {
        Target found = null;
        if (reported == null) {
            return null;
        }
        for (Target target : targets) {
            if (target.covers(reported) && (found == null || target.path.length() > found.path.length())) {
                found = target;
            }
        }
        return found;
    }

    /** @return the process the path belongs to, or {@link #UNLISTED} */
    public String processOf(String reported) {
        Target target = targetOf(reported);
        return target == null ? UNLISTED : target.process;
    }

    static IntegrityTargets parse(List<String> lines) {
        List<Target> targets = new ArrayList<>();
        for (String line : lines) {
            boolean measured = line.startsWith(MEASURED);
            if (!measured && !line.startsWith(NOT_MEASURED)) {
                continue;
            }
            String[] fields = line.substring(3).trim().split("\\s+", 2); //$NON-NLS-1$
            if (fields.length == 2 && fields[1].startsWith("/")) { //$NON-NLS-1$
                targets.add(new Target(fields[0], fields[1].trim(), measured));
            }
        }
        return new IntegrityTargets(targets);
    }

    /** @return the targets engine-setup last wrote, or none when it has not written them */
    public static IntegrityTargets read() {
        Path config = Paths.get(CONFIG);
        if (!Files.isReadable(config)) {
            return new IntegrityTargets(new ArrayList<>());
        }
        try {
            return parse(Files.readAllLines(config, StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            log.warn("Unable to read the integrity verification targets from {}: {}", CONFIG, e.getMessage()); //$NON-NLS-1$
            return new IntegrityTargets(new ArrayList<>());
        }
    }
}
