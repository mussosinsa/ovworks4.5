package org.ovirt.engine.core.bll;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Words the audit records of a self-test (security audit) or an integrity verification that did not
 * pass: one record per item naming the component and the item, and one record summarising them all.
 *
 * <p>The event list used to say that a verification failed and how many checks or files were
 * involved; which item, and on which component, was only in a log file on the engine host. The
 * records now carry both, and the summary groups the failures by component so that the answer to
 * "what failed, where" is one record.</p>
 *
 * <p>Components: {@link #ENGINE_SERVER} for the engine host itself, {@link #CLIENT} for the
 * management client (WebAdmin) - the web application files the engine host serves to the
 * administrator's browser, which the integrity verification also covers.</p>
 */
final class VerificationFailureReport {

    static final String ENGINE_SERVER = "엔진 서버"; //$NON-NLS-1$
    static final String CLIENT = "클라이언트(WebAdmin)"; //$NON-NLS-1$

    /** How many files a summary names per component before it only counts the rest. */
    static final int MAX_NAMED_FILES = 10;

    /**
     * Paths of the management client: the web applications delivered to the administrator's
     * browser, their UI plug-ins and branding.
     */
    private static final String[] CLIENT_PATH_MARKERS = {
            "/webadmin.war/", //$NON-NLS-1$
            "/userportal.war/", //$NON-NLS-1$
            "/ui-plugins/", //$NON-NLS-1$
            "/branding/", //$NON-NLS-1$
            "/usr/share/ovirt-web-ui/", //$NON-NLS-1$
    };

    private VerificationFailureReport() {
    }

    // ---------------------------------------------------------------- self-test

    /** {@code 자체시험 실패 [구성요소: 엔진 서버 | 항목: 설정 파일 권한] engine.conf has ...} */
    static String selfTestFinding(SecurityAuditRunner.Finding finding) {
        boolean failed = finding.getLevel() == SecurityAuditRunner.Finding.Level.FAILED;
        return (failed ? "자체시험 실패" : "자체시험 경고") //$NON-NLS-1$ //$NON-NLS-2$
                + " [구성요소: " + finding.getComponent() //$NON-NLS-1$
                + " | 항목: " + finding.getItem() + "] " //$NON-NLS-1$ //$NON-NLS-2$
                + finding.getText();
    }

    /**
     * {@code 자체시험 실패 요약 (timer, 2026-10-06T02:30:11+09:00): 실패 3건, 경고 1건 |
     * 엔진 서버 - 실패: 설정 파일 권한(1), TLS 인증서(2) / 경고: 백업 설정(1)}
     *
     * @param context who ran it and when, already worded, or empty
     */
    static String selfTestSummary(List<SecurityAuditRunner.Finding> findings, String context) {
        int failed = 0;
        int warned = 0;
        // component -> (failed items, warned items), each item with its count, in report order
        Map<String, Map<String, Integer>> failedBy = new LinkedHashMap<>();
        Map<String, Map<String, Integer>> warnedBy = new LinkedHashMap<>();
        List<String> components = new ArrayList<>();
        for (SecurityAuditRunner.Finding finding : findings) {
            boolean isFailure = finding.getLevel() == SecurityAuditRunner.Finding.Level.FAILED;
            if (isFailure) {
                failed++;
            } else {
                warned++;
            }
            if (!components.contains(finding.getComponent())) {
                components.add(finding.getComponent());
            }
            Map<String, Map<String, Integer>> target = isFailure ? failedBy : warnedBy;
            target.computeIfAbsent(finding.getComponent(), c -> new LinkedHashMap<>())
                    .merge(finding.getItem(), 1, Integer::sum);
        }
        StringBuilder text = new StringBuilder("자체시험 실패 요약"); //$NON-NLS-1$
        text.append(context(context)).append(": 실패 ").append(failed) //$NON-NLS-1$
                .append("건, 경고 ").append(warned).append("건"); //$NON-NLS-1$ //$NON-NLS-2$
        for (String component : components) {
            text.append(" | ").append(component).append(" -"); //$NON-NLS-1$ //$NON-NLS-2$
            boolean first = true;
            if (failedBy.containsKey(component)) {
                text.append(" 실패: ").append(items(failedBy.get(component))); //$NON-NLS-1$
                first = false;
            }
            if (warnedBy.containsKey(component)) {
                text.append(first ? " " : " / ").append("경고: ") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                        .append(items(warnedBy.get(component)));
            }
        }
        return text.toString();
    }

    private static String items(Map<String, Integer> counts) {
        List<String> parts = new ArrayList<>();
        counts.forEach((item, count) -> parts.add(item + "(" + count + ")")); //$NON-NLS-1$ //$NON-NLS-2$
        return String.join(", ", parts); //$NON-NLS-1$
    }

    // ---------------------------------------------------------------- integrity verification

    /** @return the component a file belongs to */
    static String componentOf(String path) {
        if (path != null) {
            for (String marker : CLIENT_PATH_MARKERS) {
                if (path.contains(marker)) {
                    return CLIENT;
                }
            }
        }
        return ENGINE_SERVER;
    }

    /** {@code 무결성 검증 실패 [구성요소: 엔진 서버 | 변경] A file no longer matches ...: /path} */
    static String integrityChange(IntegrityVerification.Change change) {
        return "무결성 검증 실패 [구성요소: " + componentOf(change.getPath()) //$NON-NLS-1$
                + " | " + kindName(change.getKind()) + "] " //$NON-NLS-1$ //$NON-NLS-2$
                + change.describe();
    }

    /**
     * {@code 무결성 검증 실패 요약 (timer, ...): 총 4건 (변경 2, 삭제 1, 추가 1) |
     * 엔진 서버 3건: /etc/a(변경), /etc/b(삭제), ... | 클라이언트(WebAdmin) 1건: ...}
     */
    static String integritySummary(List<IntegrityVerification.Change> changes, String context) {
        Map<IntegrityVerification.Change.Kind, Integer> byKind = new LinkedHashMap<>();
        Map<String, List<IntegrityVerification.Change>> byComponent = new LinkedHashMap<>();
        byComponent.put(ENGINE_SERVER, new ArrayList<>());
        byComponent.put(CLIENT, new ArrayList<>());
        for (IntegrityVerification.Change change : changes) {
            byKind.merge(change.getKind(), 1, Integer::sum);
            byComponent.get(componentOf(change.getPath())).add(change);
        }
        StringBuilder text = new StringBuilder("무결성 검증 실패 요약"); //$NON-NLS-1$
        text.append(context(context)).append(": 총 ").append(changes.size()).append("건 (") //$NON-NLS-1$ //$NON-NLS-2$
                .append("변경 ").append(byKind.getOrDefault(IntegrityVerification.Change.Kind.CHANGED, 0)) //$NON-NLS-1$
                .append(", 삭제 ").append(byKind.getOrDefault(IntegrityVerification.Change.Kind.REMOVED, 0)) //$NON-NLS-1$
                .append(", 추가 ").append(byKind.getOrDefault(IntegrityVerification.Change.Kind.ADDED, 0)) //$NON-NLS-1$
                .append(")"); //$NON-NLS-1$
        for (Map.Entry<String, List<IntegrityVerification.Change>> entry : byComponent.entrySet()) {
            List<IntegrityVerification.Change> files = entry.getValue();
            if (files.isEmpty()) {
                continue;
            }
            text.append(" | ").append(entry.getKey()).append(' ').append(files.size()).append("건: "); //$NON-NLS-1$ //$NON-NLS-2$
            List<String> named = new ArrayList<>();
            for (IntegrityVerification.Change change : files.subList(0, Math.min(files.size(), MAX_NAMED_FILES))) {
                named.add(change.getPath() + "(" + kindName(change.getKind()) + ")"); //$NON-NLS-1$ //$NON-NLS-2$
            }
            text.append(String.join(", ", named)); //$NON-NLS-1$
            if (files.size() > MAX_NAMED_FILES) {
                text.append(" 외 ").append(files.size() - MAX_NAMED_FILES).append("건"); //$NON-NLS-1$ //$NON-NLS-2$
            }
        }
        return text.toString();
    }

    /** The summary of a verification that could not be carried out at all. */
    static String integrityNotCarriedOut(String context, int exitCode) {
        return "무결성 검증 실패 요약" + context(context) //$NON-NLS-1$
                + ": 검증을 수행하지 못함 [구성요소: " + ENGINE_SERVER //$NON-NLS-1$
                + " | 항목: 무결성 검사(AIDE)] AIDE exit code " + exitCode; //$NON-NLS-1$
    }

    static String kindName(IntegrityVerification.Change.Kind kind) {
        switch (kind) {
        case ADDED:
            return "추가"; //$NON-NLS-1$
        case REMOVED:
            return "삭제"; //$NON-NLS-1$
        default:
            return "변경"; //$NON-NLS-1$
        }
    }

    private static String context(String context) {
        return context == null || context.trim().isEmpty() ? "" : " (" + context.trim() + ")"; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    }
}
