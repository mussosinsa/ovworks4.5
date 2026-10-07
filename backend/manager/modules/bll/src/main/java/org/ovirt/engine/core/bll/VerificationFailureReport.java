package org.ovirt.engine.core.bll;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.ovirt.engine.core.common.AuditLogType;

/**
 * Words the audit records of a self-test (security audit) and an integrity verification: one record
 * for every item of every process - passed, failed, warned about or not applicable - naming the
 * process and the item, and for a run that did not pass one record with the details of every item
 * that did not.
 *
 * <p>The processes are the six main processes of the engine host: ovirt-engine,
 * ovirt-engine-proxy (httpd), postgresql, ovirt-engine-dwhd, ovirt-websocket-proxy and
 * ovirt-provider-ovn. The self-test checks, for each, that it runs, its executables and its
 * configuration files by exact name; the integrity verification measures the same files.</p>
 */
final class VerificationFailureReport {

    /** What an item is recorded about when nothing else names it. */
    static final String ENGINE_SERVER = "엔진 서버"; //$NON-NLS-1$

    /** How many files the detail record lists before it only counts the rest. */
    static final int MAX_DETAILED_FILES = 200;

    /** Between entries: each on a line of its own where the message is shown with its lines. */
    static final String NEW_ENTRY = "\n"; //$NON-NLS-1$

    /** One record for the audit log: its type and its message. */
    static final class Record {
        private final AuditLogType type;
        private final String message;

        Record(AuditLogType type, String message) {
            this.type = type;
            this.message = message;
        }

        AuditLogType getType() {
            return type;
        }

        String getMessage() {
            return message;
        }
    }

    private VerificationFailureReport() {
    }

    // ---------------------------------------------------------------- self-test

    /** {@code 자체시험 실패 [프로세스: ovirt-engine | 항목: 설정 파일] /etc/... : ...} */
    static String selfTestFinding(SecurityAuditRunner.Finding finding) {
        return "자체시험 " + levelName(finding.getLevel()) //$NON-NLS-1$
                + " [프로세스: " + finding.getComponent() //$NON-NLS-1$
                + " | 항목: " + finding.getItem() + "] " //$NON-NLS-1$ //$NON-NLS-2$
                + finding.getText();
    }

    /** The record of one self-test item, of the type its result calls for. */
    static Record selfTestRecord(SecurityAuditRunner.Finding finding) {
        AuditLogType type;
        switch (finding.getLevel()) {
        case FAILED:
            type = AuditLogType.SECURITY_AUDIT_FAILED;
            break;
        case WARNING:
            type = AuditLogType.SECURITY_AUDIT_WARNING;
            break;
        default:
            type = AuditLogType.SECURITY_SELF_TEST_ITEM_RESULT;
        }
        return new Record(type, selfTestFinding(finding));
    }

    private static String levelName(SecurityAuditRunner.Finding.Level level) {
        switch (level) {
        case PASSED:
            return "성공"; //$NON-NLS-1$
        case FAILED:
            return "실패"; //$NON-NLS-1$
        case WARNING:
            return "경고"; //$NON-NLS-1$
        default:
            return "제외"; //$NON-NLS-1$
        }
    }

    /**
     * Every failed and warned item of a self-test in full, one numbered entry each:
     * <pre>
     * 자체시험 실패 상세 (timer, 2026-10-06T02:30:11+09:00): 실패 2건, 경고 1건
     * [1] 실패 | 프로세스: ovirt-engine | 항목: 설정 파일 | /etc/.../10-setup-database.conf: ...
     * [2] 실패 | 프로세스: ovirt-engine-proxy | 항목: 프로세스 실행 상태 | httpd.service: 실행 중이 아님
     * [3] 경고 | 프로세스: postgresql | 항목: 설정 파일 | /var/lib/pgsql/data/pg_hba.conf: ...
     * </pre>
     * Failures first, then warnings, each in the order the audit reported them; the items that
     * passed or did not apply are recorded one by one and not repeated here.
     *
     * @param context who ran it and when, already worded, or empty
     */
    static String selfTestDetail(List<SecurityAuditRunner.Finding> findings, String context) {
        List<SecurityAuditRunner.Finding> failed = new ArrayList<>();
        List<SecurityAuditRunner.Finding> warned = new ArrayList<>();
        for (SecurityAuditRunner.Finding finding : findings) {
            if (finding.getLevel() == SecurityAuditRunner.Finding.Level.FAILED) {
                failed.add(finding);
            } else if (finding.getLevel() == SecurityAuditRunner.Finding.Level.WARNING) {
                warned.add(finding);
            }
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
                    .append(" | 프로세스: ").append(finding.getComponent()) //$NON-NLS-1$
                    .append(" | 항목: ").append(finding.getItem()) //$NON-NLS-1$
                    .append(" | ").append(finding.getText()); //$NON-NLS-1$
        }
        return text.toString();
    }

    // ---------------------------------------------------------------- integrity verification

    /** {@code 무결성 검증 실패 [프로세스: ovirt-engine | 변경] A file no longer matches ...: /path} */
    static String integrityChange(IntegrityVerification.Change change, IntegrityTargets targets) {
        return "무결성 검증 실패 [프로세스: " + targets.processOf(change.getPath()) //$NON-NLS-1$
                + " | " + kindName(change.getKind()) + "] " //$NON-NLS-1$ //$NON-NLS-2$
                + change.describe();
    }

    /**
     * {@code 무결성 검증 성공 [프로세스: ovirt-engine | 파일 12개] 기준값(무결성 데이터베이스)과 일치: /a, /b}:
     * every file of one process that matched, in one record.
     */
    static String integrityMatched(String process, List<IntegrityTargets.Target> targets) {
        return "무결성 검증 성공 [프로세스: " + process + " | 파일 " + targets.size() + "개] " //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                + "기준값(무결성 데이터베이스)과 일치: " + paths(targets); //$NON-NLS-1$
    }

    /** The files of one process not measured because they were not there when the baseline was taken. */
    static String integrityNotMeasured(String process, List<IntegrityTargets.Target> targets) {
        return "무결성 검증 제외 [프로세스: " + process + " | 파일 " + targets.size() + "개] " //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                + "기준값 생성 시 파일 없음(선택 파일 또는 미설치): " + paths(targets); //$NON-NLS-1$
    }

    private static String paths(List<IntegrityTargets.Target> targets) {
        StringBuilder text = new StringBuilder();
        for (IntegrityTargets.Target target : targets) {
            text.append(text.length() == 0 ? "" : ", ").append(target.getPath()); //$NON-NLS-1$ //$NON-NLS-2$
        }
        return text.toString();
    }

    /**
     * The records of one verification, process by process in the order of the list: each file AIDE
     * reported as changed, removed or added on a record of its own, then one record with every file
     * of the process that matched its baseline, and one with those not measured; then whatever AIDE
     * reported that is on no list (the baseline itself among them, when it no longer matches its
     * seal).
     *
     * <p>Success is recorded once per process rather than once per file, with the files named in
     * it: a verification runs at every start and twice a day, and a record per file that matched
     * would bury the ones that did not.</p>
     */
    static List<Record> integrityRecords(IntegrityTargets targets, List<IntegrityVerification.Change> changes) {
        List<Record> records = new ArrayList<>();
        List<IntegrityVerification.Change> unlisted = new ArrayList<>(changes);
        Map<String, List<IntegrityTargets.Target>> byProcess = new LinkedHashMap<>();
        for (IntegrityTargets.Target target : targets.getTargets()) {
            byProcess.computeIfAbsent(target.getProcess(), p -> new ArrayList<>()).add(target);
        }
        for (Map.Entry<String, List<IntegrityTargets.Target>> process : byProcess.entrySet()) {
            List<IntegrityTargets.Target> matched = new ArrayList<>();
            List<IntegrityTargets.Target> notMeasured = new ArrayList<>();
            for (IntegrityTargets.Target target : process.getValue()) {
                boolean changed = false;
                for (IntegrityVerification.Change change : changes) {
                    if (targets.targetOf(change.getPath()) == target) {
                        changed = true;
                        unlisted.remove(change);
                        records.add(integrityChangeRecord(change, targets));
                    }
                }
                if (!changed) {
                    (target.isMeasured() ? matched : notMeasured).add(target);
                }
            }
            if (!matched.isEmpty()) {
                records.add(new Record(AuditLogType.INTEGRITY_VERIFICATION_FILE_RESULT,
                        integrityMatched(process.getKey(), matched)));
            }
            if (!notMeasured.isEmpty()) {
                records.add(new Record(AuditLogType.INTEGRITY_VERIFICATION_FILE_RESULT,
                        integrityNotMeasured(process.getKey(), notMeasured)));
            }
        }
        for (IntegrityVerification.Change change : unlisted) {
            records.add(integrityChangeRecord(change, targets));
        }
        return records;
    }

    private static Record integrityChangeRecord(IntegrityVerification.Change change, IntegrityTargets targets) {
        return new Record(change.getKind() == IntegrityVerification.Change.Kind.REMOVED
                ? AuditLogType.INTEGRITY_VERIFICATION_FILE_MISSING
                : AuditLogType.INTEGRITY_VERIFICATION_FILE_MODIFIED,
                integrityChange(change, targets));
    }

    /**
     * Every file the integrity verification reported, one numbered entry each:
     * <pre>
     * 무결성 검증 실패 상세 (webadmin, ...): 총 2건 (변경 1, 삭제 1, 추가 0)
     * [1] 변경 | 프로세스: ovirt-engine | /etc/ovirt-engine/engine.conf.d/10-setup-pki.conf | ...
     * [2] 삭제 | 프로세스: ovirt-engine-proxy | /etc/httpd/conf.d/ssl.conf | ...
     * </pre>
     * In the order AIDE reported them. An upgrade can report many files under engine.ear, so
     * beyond {@link #MAX_DETAILED_FILES} the rest are counted and the report named.
     *
     * @param report the AIDE report the complete list is in, or null
     */
    static String integrityDetail(List<IntegrityVerification.Change> changes, IntegrityTargets targets,
            String context, Path report) {
        Map<IntegrityVerification.Change.Kind, Integer> byKind = new LinkedHashMap<>();
        for (IntegrityVerification.Change change : changes) {
            byKind.merge(change.getKind(), 1, Integer::sum);
        }
        StringBuilder text = new StringBuilder("무결성 검증 실패 상세"); //$NON-NLS-1$
        text.append(context(context)).append(": 총 ").append(changes.size()).append("건 (") //$NON-NLS-1$ //$NON-NLS-2$
                .append("변경 ").append(byKind.getOrDefault(IntegrityVerification.Change.Kind.CHANGED, 0)) //$NON-NLS-1$
                .append(", 삭제 ").append(byKind.getOrDefault(IntegrityVerification.Change.Kind.REMOVED, 0)) //$NON-NLS-1$
                .append(", 추가 ").append(byKind.getOrDefault(IntegrityVerification.Change.Kind.ADDED, 0)) //$NON-NLS-1$
                .append(")"); //$NON-NLS-1$
        int listed = Math.min(changes.size(), MAX_DETAILED_FILES);
        for (int i = 0; i < listed; i++) {
            IntegrityVerification.Change change = changes.get(i);
            text.append(NEW_ENTRY).append('[').append(i + 1).append("] ") //$NON-NLS-1$
                    .append(kindName(change.getKind()))
                    .append(" | 프로세스: ").append(targets.processOf(change.getPath())) //$NON-NLS-1$
                    .append(" | ").append(change.getPath()) //$NON-NLS-1$
                    .append(" | ").append(whatHappened(change.getKind())); //$NON-NLS-1$
        }
        if (changes.size() > listed) {
            text.append(NEW_ENTRY).append("외 ").append(changes.size() - listed).append("건") //$NON-NLS-1$ //$NON-NLS-2$
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
                + ": 검증을 수행하지 못함 [대상: " + ENGINE_SERVER //$NON-NLS-1$
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
