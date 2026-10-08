package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Paths;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.common.AuditLogType;

/**
 * The audit log has to record the result of every item of every main process - which passed,
 * which failed and what was found, which did not apply - for the self-test and the integrity
 * verification alike, and for a run that did not pass every failed item in full.
 */
public class VerificationFailureReportTest {

    private static final String OUTPUT = String.join("\n",
            "[PASS] [ovirt-engine/프로세스 실행 상태] ovirt-engine.service: 실행 중(active, PID 10, 계정 ovirt)",
            "\u001B[0;31m[FAIL]\u001B[0m [ovirt-engine/설정 파일] "
                    + "/etc/ovirt-engine/engine.conf.d/10-setup-database.conf: 비밀정보 파일에 기타 사용자 접근 권한",
            "[WARN] [postgresql/설정 파일] /var/lib/pgsql/data/pg_hba.conf: 권한이 없어 확인할 수 없음",
            "[FAIL] [ovirt-engine-proxy/프로세스 실행 상태] httpd.service: 실행 중이 아님(inactive)",
            "[SKIP] [ovirt-provider-ovn/프로세스 실행 상태] ovirt-provider-ovn.service: 설치되지 않음 - 점검 대상 아님",
            "[FAIL] an untagged line from an older audit script");

    @Test
    void everyItemIsRecordedWithItsProcessItemAndResult() {
        List<SecurityAuditRunner.Finding> findings = SecurityAuditRunner.findingsIn(OUTPUT);
        assertEquals(6, findings.size());

        VerificationFailureReport.Record passed = VerificationFailureReport.selfTestRecord(findings.get(0));
        assertEquals(AuditLogType.SECURITY_SELF_TEST_ITEM_RESULT, passed.getType());
        assertEquals("자체시험 성공 : [프로세스: ovirt-engine | 항목: 프로세스 실행 상태] "
                + "ovirt-engine.service: 실행 중(active, PID 10, 계정 ovirt)", passed.getMessage());

        VerificationFailureReport.Record failed = VerificationFailureReport.selfTestRecord(findings.get(1));
        assertEquals(AuditLogType.SECURITY_AUDIT_FAILED, failed.getType());
        assertEquals("자체시험 실패 : [프로세스: ovirt-engine | 항목: 설정 파일] "
                + "/etc/ovirt-engine/engine.conf.d/10-setup-database.conf: 비밀정보 파일에 기타 사용자 접근 권한",
                failed.getMessage());

        assertEquals(AuditLogType.SECURITY_AUDIT_WARNING,
                VerificationFailureReport.selfTestRecord(findings.get(2)).getType());

        VerificationFailureReport.Record skipped = VerificationFailureReport.selfTestRecord(findings.get(4));
        assertEquals(AuditLogType.SECURITY_SELF_TEST_ITEM_RESULT, skipped.getType());
        assertTrue(skipped.getMessage().startsWith("자체시험 제외 : [프로세스: ovirt-provider-ovn | "));
    }

    private static final ZoneId SEOUL = ZoneId.of("Asia/Seoul");
    private static final Instant RAN_AT = Instant.parse("2026-10-08T00:00:11Z");

    @Test
    void aFailedRunSaysSelfTestFailedAndWhyWhoeverRanIt() {
        List<SecurityAuditRunner.Finding> findings = SecurityAuditRunner.findingsIn(OUTPUT);
        String expectedReason = "자체시험 실패 : ovirt-engine/설정 파일 - "
                + "/etc/ovirt-engine/engine.conf.d/10-setup-database.conf: 비밀정보 파일에 기타 사용자 접근 권한; "
                + "ovirt-engine-proxy/프로세스 실행 상태 - httpd.service: 실행 중이 아님(inactive); "
                + "엔진 서버/기타 - an untagged line from an older audit script";

        SecurityAuditRunner.Result atStart = new SecurityAuditRunner.Result(RAN_AT, "FAIL", "engine-start",
                new SecurityAuditRunner.Summary(40, 1, 3), null);
        assertEquals(expectedReason + " (엔진 기동 전, 2026-10-08 09:00:11, 성공 40·경고 1·실패 3)",
                StartupSecurityAuditManager.failureMessage(atStart, findings, SEOUL));

        SecurityAuditRunner.Result timer = new SecurityAuditRunner.Result(RAN_AT, "FAIL", "timer",
                new SecurityAuditRunner.Summary(40, 1, 3), null);
        assertTrue(StartupSecurityAuditManager.failureMessage(timer, findings, SEOUL)
                .endsWith("(정기 점검, 2026-10-08 09:00:11, 성공 40·경고 1·실패 3)"));

        assertEquals(expectedReason + " (관리화면 admin, 2026-10-08 09:00:11, 성공 1·경고 1·실패 3, 종료 코드 20)",
                SecurityAuditCommand.failureMessage(findings, 20, "admin", RAN_AT, SEOUL));
    }

    @Test
    void aFailedRunNamesThreeFailuresAndCountsTheRest() {
        List<SecurityAuditRunner.Finding> findings = SecurityAuditRunner.findingsIn(OUTPUT);
        String reason = VerificationFailureReport.failureReason(findings, 5);
        assertTrue(reason.endsWith("an untagged line from an older audit script 외 2건"), reason);
        assertEquals("실패 항목 2건 (항목 내용을 읽지 못함)",
                VerificationFailureReport.failureReason(new ArrayList<>(), 2));
        assertEquals("점검이 실패로 끝났으나 실패 항목을 확인하지 못함",
                VerificationFailureReport.failureReason(new ArrayList<>(), 0));
    }

    @Test
    void anUntaggedLineStillNamesAComponent() {
        SecurityAuditRunner.Finding untagged = SecurityAuditRunner.findingsIn(OUTPUT).get(5);
        assertEquals("엔진 서버", untagged.getComponent());
        assertEquals("기타", untagged.getItem());
    }

    @Test
    void theSelfTestDetailListsEveryItemThatDidNotPassFailuresFirst() {
        assertEquals("자체시험 실패 상세 (timer, 2026-10-06T02:30:11+09:00): 실패 3건, 경고 1건\n"
                + "[1] 실패 | 프로세스: ovirt-engine | 항목: 설정 파일 | "
                + "/etc/ovirt-engine/engine.conf.d/10-setup-database.conf: 비밀정보 파일에 기타 사용자 접근 권한\n"
                + "[2] 실패 | 프로세스: ovirt-engine-proxy | 항목: 프로세스 실행 상태 | httpd.service: 실행 중이 아님(inactive)\n"
                + "[3] 실패 | 프로세스: 엔진 서버 | 항목: 기타 | an untagged line from an older audit script\n"
                + "[4] 경고 | 프로세스: postgresql | 항목: 설정 파일 | "
                + "/var/lib/pgsql/data/pg_hba.conf: 권한이 없어 확인할 수 없음",
                VerificationFailureReport.selfTestDetail(
                        SecurityAuditRunner.findingsIn(OUTPUT), "timer, 2026-10-06T02:30:11+09:00"));
    }

    private static final IntegrityTargets TARGETS = IntegrityTargets.parse(Arrays.asList(
            "# --- ovirt-engine ---",
            "#@ ovirt-engine /usr/share/ovirt-engine/engine.ear",
            "/usr/share/ovirt-engine/engine\\.ear/ OVWORKS_CONTENT",
            "#@ ovirt-engine /etc/ovirt-engine/engine.conf.d/10-setup-database.conf",
            "#- ovirt-engine /etc/ovirt-engine/engine.conf.d/10-setup-java.conf",
            "#@ ovirt-engine-proxy /etc/httpd/conf.d/ssl.conf"));

    @Test
    void failuresAreRecordedPerFileAndSuccessOncePerProcess() {
        List<IntegrityVerification.Change> changes = new ArrayList<>();
        changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.CHANGED,
                "/usr/share/ovirt-engine/engine.ear/bll.jar"));
        changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.REMOVED,
                "/etc/httpd/conf.d/ssl.conf"));
        changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.CHANGED,
                "/var/lib/aide/ovworks.db.gz"));

        List<VerificationFailureReport.Record> records = VerificationFailureReport.integrityRecords(TARGETS, changes);

        assertEquals(5, records.size());
        assertEquals(AuditLogType.INTEGRITY_VERIFICATION_FILE_MODIFIED, records.get(0).getType());
        assertTrue(records.get(0).getMessage().startsWith("무결성 검증 실패 [프로세스: ovirt-engine | 변경] "),
                records.get(0).getMessage());
        assertEquals(AuditLogType.INTEGRITY_VERIFICATION_FILE_RESULT, records.get(1).getType());
        assertEquals("무결성 검증 성공 [프로세스: ovirt-engine | 파일 1개] 기준값(무결성 데이터베이스)과 일치: "
                + "/etc/ovirt-engine/engine.conf.d/10-setup-database.conf", records.get(1).getMessage());
        assertEquals("무결성 검증 제외 [프로세스: ovirt-engine | 파일 1개] 기준값 생성 시 파일 없음(선택 파일 또는 미설치): "
                + "/etc/ovirt-engine/engine.conf.d/10-setup-java.conf", records.get(2).getMessage());
        assertEquals(AuditLogType.INTEGRITY_VERIFICATION_FILE_MISSING, records.get(3).getType());
        assertTrue(records.get(3).getMessage().startsWith("무결성 검증 실패 [프로세스: ovirt-engine-proxy | 삭제] "));
        // The baseline that no longer matches its seal is named as the baseline.
        assertTrue(records.get(4).getMessage().startsWith("무결성 검증 실패 [프로세스: 무결성 기준값 | 변경] "),
                records.get(4).getMessage());
    }

    @Test
    void aCleanRunRecordsEachProcessOnceWithItsFiles() {
        List<VerificationFailureReport.Record> records =
                VerificationFailureReport.integrityRecords(TARGETS, new ArrayList<>());
        assertEquals(3, records.size());
        assertEquals("무결성 검증 성공 [프로세스: ovirt-engine | 파일 2개] 기준값(무결성 데이터베이스)과 일치: "
                + "/usr/share/ovirt-engine/engine.ear, /etc/ovirt-engine/engine.conf.d/10-setup-database.conf",
                records.get(0).getMessage());
        assertTrue(records.get(2).getMessage().startsWith("무결성 검증 성공 [프로세스: ovirt-engine-proxy | 파일 1개]"));
        for (VerificationFailureReport.Record record : records) {
            assertEquals(AuditLogType.INTEGRITY_VERIFICATION_FILE_RESULT, record.getType());
        }
    }

    @Test
    void theIntegrityDetailListsEveryFileWithProcessAndWhatHappened() {
        List<IntegrityVerification.Change> changes = new ArrayList<>();
        changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.CHANGED,
                "/etc/ovirt-engine/engine.conf.d/10-setup-database.conf"));
        changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.REMOVED,
                "/etc/httpd/conf.d/ssl.conf"));
        assertEquals("무결성 검증 실패 상세 (webadmin): 총 2건 (변경 1, 삭제 1, 추가 0)\n"
                + "[1] 변경 | 프로세스: ovirt-engine | /etc/ovirt-engine/engine.conf.d/10-setup-database.conf"
                + " | 무결성 데이터베이스와 내용·속성이 다름\n"
                + "[2] 삭제 | 프로세스: ovirt-engine-proxy | /etc/httpd/conf.d/ssl.conf"
                + " | 무결성 데이터베이스에 기록된 파일이 없어짐",
                VerificationFailureReport.integrityDetail(changes, TARGETS, "webadmin", null));
    }

    @Test
    void aVeryLongListPointsToTheReport() {
        List<IntegrityVerification.Change> changes = new ArrayList<>();
        for (int i = 0; i < VerificationFailureReport.MAX_DETAILED_FILES + 3; i++) {
            changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.CHANGED,
                    "/usr/share/ovirt-engine/engine.ear/f" + i));
        }
        String detail = VerificationFailureReport.integrityDetail(changes, TARGETS, "",
                Paths.get("/var/log/ovirt-engine/integrity-verification-1.log"));
        assertTrue(detail.contains("[200] 변경 | 프로세스: ovirt-engine"), detail);
        assertTrue(detail.endsWith("\n외 3건 (전체 목록: /var/log/ovirt-engine/integrity-verification-1.log)"));
    }

    @Test
    void aVerificationThatCouldNotRunSaysSo() {
        assertEquals("무결성 검증 실패 상세 (timer): 검증을 수행하지 못함 "
                + "[대상: 엔진 서버 | 항목: 무결성 검사(AIDE)] AIDE exit code 17",
                VerificationFailureReport.integrityNotCarriedOut("timer", 17));
    }
}
