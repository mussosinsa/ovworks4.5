package org.ovirt.engine.core.bll;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Words the audit records of a self-test (security audit) or an integrity verification that did not
 * pass: one record per item naming the component and the item, and one record with the details of
 * every failed item.
 *
 * <p>The event list used to say that a verification failed and how many checks or files were
 * involved; which item, and on which component, was only in a log file on the engine host. The
 * records now carry both, and the detail record lists every failed item in full - component, item
 * and what was found - so that the answer to "what failed, where, and how" is one record.</p>
 *
 * <p>Components: {@link #ENGINE_SERVER} for the engine host itself, {@link #CLIENT} for the
 * management client (WebAdmin) - the web application files the engine host serves to the
 * administrator's browser, which the integrity verification also covers.</p>
 */
final class VerificationFailureReport {

    static final String ENGINE_SERVER = "엔진 서버"; //$NON-NLS-1$
    static final String CLIENT = "클라이언트(WebAdmin)"; //$NON-NLS-1$

    /** How many files the detail record lists before it only counts the rest. */
    static final int MAX_DETAILED_FILES = 200;

    /** Between entries: each on a line of its own where the message is shown with its lines. */
    static final String NEW_ENTRY = "\n"; //$NON-NLS-1$

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
     * Every failed and warned item of a self-test in full, one numbered entry each:
     * <pre>
     * 자체시험 실패 상세 (timer, 2026-10-06T02:30:11+09:00): 실패 2건, 경고 1건
     * [1] 실패 | 구성요소: 엔진 서버 | 항목: 설정 파일 권한 | engine.conf has insecure permissions (644)
     * [2] 실패 | 구성요소: 엔진 서버 | 항목: TLS 인증서 | Certificate apache.cer has expired
     * [3] 경고 | 구성요소: 엔진 서버 | 항목: 백업 설정 | No backup in the last 7 days
     * </pre>
     * Failures first, then warnings, each in the order the audit reported them.
     *
     * @param context who ran it and when, already worded, or empty
     */
    static String selfTestDetail(List<SecurityAuditRunner.Finding> findings, String context) {
        List<SecurityAuditRunner.Finding> failed = new ArrayList<>();
        List<SecurityAuditRunner.Finding> warned = new ArrayList<>();
        for (SecurityAuditRunner.Finding finding : findings) {
            (finding.getLevel() == SecurityAuditRunner.Finding.Level.FAILED ? failed : warned).add(finding);
        }
        StringBuilder text = new StringBuilder("자체시험 실패 상세"); //$NON-NLS-1$
        text.append(context(context)).append(": 실패 ").append(failed.size()) //$NON-NLS-1$
                .append("건, 경고 ").append(warned.size()).append("건"); //$NON-NLS-1$ //$NON-NLS-2$
        int number = 0;
        List<SecurityAuditRunner.Finding> ordered = new ArrayList<>(failed);
        ordered.addAll(warned);
        for (SecurityAuditRunner.Finding finding : ordered) {
            boolean isFailure = finding.getLevel() == SecurityAuditRunner.Finding.Level.FAILED;
            text.append(NEW_ENTRY).append('[').append(++number).append("] ") //$NON-NLS-1$
                    .append(isFailure ? "실패" : "경고") //$NON-NLS-1$ //$NON-NLS-2$
                    .append(" | 구성요소: ").append(finding.getComponent()) //$NON-NLS-1$
                    .append(" | 항목: ").append(finding.getItem()) //$NON-NLS-1$
                    .append(" | ").append(finding.getText()); //$NON-NLS-1$
        }
        return text.toString();
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
     * Every file the integrity verification reported, one numbered entry each:
     * <pre>
     * 무결성 검증 실패 상세 (webadmin, ...): 총 3건 (변경 1, 삭제 1, 추가 1)
     * [1] 변경 | 구성요소: 엔진 서버 | /etc/ovirt-engine/engine.conf | A file no longer matches the integrity database
     * [2] 삭제 | 구성요소: 엔진 서버 | /usr/share/ovirt-engine/bin/engine-config.sh | ...
     * [3] 추가 | 구성요소: 클라이언트(WebAdmin) | .../webadmin.war/x.js | ...
     * </pre>
     * Engine server files first, then the client's. A package update can report thousands of files,
     * so beyond {@link #MAX_DETAILED_FILES} the rest are counted and the report named.
     *
     * @param report the AIDE report the complete list is in, or null
     */
    static String integrityDetail(List<IntegrityVerification.Change> changes, String context, Path report) {
        Map<IntegrityVerification.Change.Kind, Integer> byKind = new LinkedHashMap<>();
        List<IntegrityVerification.Change> ordered = new ArrayList<>();
        List<IntegrityVerification.Change> client = new ArrayList<>();
        for (IntegrityVerification.Change change : changes) {
            byKind.merge(change.getKind(), 1, Integer::sum);
            (CLIENT.equals(componentOf(change.getPath())) ? client : ordered).add(change);
        }
        ordered.addAll(client);
        StringBuilder text = new StringBuilder("무결성 검증 실패 상세"); //$NON-NLS-1$
        text.append(context(context)).append(": 총 ").append(changes.size()).append("건 (") //$NON-NLS-1$ //$NON-NLS-2$
                .append("변경 ").append(byKind.getOrDefault(IntegrityVerification.Change.Kind.CHANGED, 0)) //$NON-NLS-1$
                .append(", 삭제 ").append(byKind.getOrDefault(IntegrityVerification.Change.Kind.REMOVED, 0)) //$NON-NLS-1$
                .append(", 추가 ").append(byKind.getOrDefault(IntegrityVerification.Change.Kind.ADDED, 0)) //$NON-NLS-1$
                .append(")"); //$NON-NLS-1$
        int listed = Math.min(ordered.size(), MAX_DETAILED_FILES);
        for (int i = 0; i < listed; i++) {
            IntegrityVerification.Change change = ordered.get(i);
            text.append(NEW_ENTRY).append('[').append(i + 1).append("] ") //$NON-NLS-1$
                    .append(kindName(change.getKind()))
                    .append(" | 구성요소: ").append(componentOf(change.getPath())) //$NON-NLS-1$
                    .append(" | ").append(change.getPath()) //$NON-NLS-1$
                    .append(" | ").append(whatHappened(change.getKind())); //$NON-NLS-1$
        }
        if (ordered.size() > listed) {
            text.append(NEW_ENTRY).append("외 ").append(ordered.size() - listed).append("건") //$NON-NLS-1$ //$NON-NLS-2$
                    .append(report == null ? "" : " (전체 목록: " + report + ")"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        }
        return text.toString();
    }

    private static String whatHappened(IntegrityVerification.Change.Kind kind) {
        switch (kind) {
        case ADDED:
            return "무결성 데이터베이스에 없는 파일이 생김"; //$NON-NLS-1$
        case REMOVED:
            return "무결성 데이터베이스에 기록된 파일이 없어짐"; //$NON-NLS-1$
        default:
            return "무결성 데이터베이스와 내용·속성이 다름"; //$NON-NLS-1$
        }
    }

    /** The details of a verification that could not be carried out at all. */
    static String integrityNotCarriedOut(String context, int exitCode) {
        return "무결성 검증 실패 상세" + context(context) //$NON-NLS-1$
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
