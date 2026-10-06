package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * A failed self-test or integrity verification has to say in the event list which item failed, on
 * which component and what was found - every item in full, not a count.
 */
public class VerificationFailureReportTest {

    private static final String OUTPUT = String.join("\n",
            "[PASS] engine.conf permissions",
            "\u001B[0;31m[FAIL]\u001B[0m [엔진 서버/설정 파일 권한] engine.conf has insecure permissions (644)",
            "[WARN] [엔진 서버/백업 설정] No backup in the last 7 days",
            "[FAIL] [엔진 서버/TLS 인증서] Certificate apache.cer has expired",
            "[FAIL] an untagged line from an older audit script");

    @Test
    void eachFindingNamesItsComponentAndItem() {
        List<SecurityAuditRunner.Finding> findings = SecurityAuditRunner.findingsIn(OUTPUT);
        assertEquals(4, findings.size());
        SecurityAuditRunner.Finding first = findings.get(0);
        assertEquals("엔진 서버", first.getComponent());
        assertEquals("설정 파일 권한", first.getItem());
        assertEquals("engine.conf has insecure permissions (644)", first.getText());
        assertEquals("자체시험 실패 [구성요소: 엔진 서버 | 항목: 설정 파일 권한] "
                + "engine.conf has insecure permissions (644)",
                VerificationFailureReport.selfTestFinding(first));
    }

    @Test
    void anUntaggedLineStillNamesAComponent() {
        SecurityAuditRunner.Finding untagged = SecurityAuditRunner.findingsIn(OUTPUT).get(3);
        assertEquals("엔진 서버", untagged.getComponent());
        assertEquals("기타", untagged.getItem());
    }

    @Test
    void theSelfTestDetailListsEveryItemInFullFailuresFirst() {
        assertEquals("자체시험 실패 상세 (timer, 2026-10-06T02:30:11+09:00): 실패 3건, 경고 1건\n"
                + "[1] 실패 | 구성요소: 엔진 서버 | 항목: 설정 파일 권한 | engine.conf has insecure permissions (644)\n"
                + "[2] 실패 | 구성요소: 엔진 서버 | 항목: TLS 인증서 | Certificate apache.cer has expired\n"
                + "[3] 실패 | 구성요소: 엔진 서버 | 항목: 기타 | an untagged line from an older audit script\n"
                + "[4] 경고 | 구성요소: 엔진 서버 | 항목: 백업 설정 | No backup in the last 7 days",
                VerificationFailureReport.selfTestDetail(
                        SecurityAuditRunner.findingsIn(OUTPUT), "timer, 2026-10-06T02:30:11+09:00"));
    }

    @Test
    void integrityFilesAreAttributedToTheEngineServerOrTheClient() {
        assertEquals("엔진 서버", VerificationFailureReport.componentOf("/etc/ovirt-engine/engine.conf"));
        assertEquals("클라이언트(WebAdmin)", VerificationFailureReport.componentOf(
                "/usr/share/ovirt-engine/engine.ear/webadmin.war/webadmin/webadmin.nocache.js"));
        assertEquals("클라이언트(WebAdmin)",
                VerificationFailureReport.componentOf("/usr/share/ovirt-engine/ui-plugins/dashboard.json"));
    }

    @Test
    void theIntegrityDetailListsEveryFileWithComponentAndWhatHappened() {
        List<IntegrityVerification.Change> changes = new ArrayList<>();
        changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.ADDED,
                "/usr/share/ovirt-engine/engine.ear/webadmin.war/x.js"));
        changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.CHANGED,
                "/etc/ovirt-engine/engine.conf"));
        changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.REMOVED,
                "/usr/share/ovirt-engine/bin/engine-config.sh"));
        assertEquals("무결성 검증 실패 상세 (webadmin): 총 3건 (변경 1, 삭제 1, 추가 1)\n"
                + "[1] 변경 | 구성요소: 엔진 서버 | /etc/ovirt-engine/engine.conf | 무결성 데이터베이스와 내용·속성이 다름\n"
                + "[2] 삭제 | 구성요소: 엔진 서버 | /usr/share/ovirt-engine/bin/engine-config.sh"
                + " | 무결성 데이터베이스에 기록된 파일이 없어짐\n"
                + "[3] 추가 | 구성요소: 클라이언트(WebAdmin) | /usr/share/ovirt-engine/engine.ear/webadmin.war/x.js"
                + " | 무결성 데이터베이스에 없는 파일이 생김",
                VerificationFailureReport.integrityDetail(changes, "webadmin", null));
        assertTrue(VerificationFailureReport.integrityChange(changes.get(2))
                .startsWith("무결성 검증 실패 [구성요소: 엔진 서버 | 삭제] "));
    }

    @Test
    void aVeryLongListPointsToTheReport() {
        List<IntegrityVerification.Change> changes = new ArrayList<>();
        for (int i = 0; i < VerificationFailureReport.MAX_DETAILED_FILES + 3; i++) {
            changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.CHANGED, "/etc/f" + i));
        }
        String detail = VerificationFailureReport.integrityDetail(changes, "",
                Paths.get("/var/log/ovirt-engine/integrity-verification-1.log"));
        assertTrue(detail.contains("[200] 변경"), detail);
        assertTrue(detail.endsWith("\n외 3건 (전체 목록: /var/log/ovirt-engine/integrity-verification-1.log)"));
    }

    @Test
    void aVerificationThatCouldNotRunSaysSo() {
        assertEquals("무결성 검증 실패 상세 (timer): 검증을 수행하지 못함 "
                + "[구성요소: 엔진 서버 | 항목: 무결성 검사(AIDE)] AIDE exit code 17",
                VerificationFailureReport.integrityNotCarriedOut("timer", 17));
    }
}
