package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * A failed self-test or integrity verification has to say in the event list which item failed and
 * on which component, and one record has to sum them up.
 */
public class VerificationFailureReportTest {

    private static final String OUTPUT = String.join("\n",
            "[PASS] engine.conf permissions",
            "\u001B[0;31m[FAIL]\u001B[0m [엔진 서버/설정 파일 권한] engine.conf has insecure permissions (644)",
            "[FAIL] [엔진 서버/TLS 인증서] Certificate apache.cer has expired",
            "[FAIL] [엔진 서버/TLS 인증서] Certificate engine.cer has expired",
            "[WARN] [엔진 서버/백업 설정] No backup in the last 7 days",
            "[FAIL] an untagged line from an older audit script");

    @Test
    void eachFindingNamesItsComponentAndItem() {
        List<SecurityAuditRunner.Finding> findings = SecurityAuditRunner.findingsIn(OUTPUT);
        assertEquals(5, findings.size());
        SecurityAuditRunner.Finding first = findings.get(0);
        assertEquals("엔진 서버", first.getComponent());
        assertEquals("설정 파일 권한", first.getItem());
        assertEquals("engine.conf has insecure permissions (644)", first.getText());
        assertEquals("자체시험 실패 [구성요소: 엔진 서버 | 항목: 설정 파일 권한] "
                + "engine.conf has insecure permissions (644)",
                VerificationFailureReport.selfTestFinding(first));
        assertEquals("자체시험 경고 [구성요소: 엔진 서버 | 항목: 백업 설정] No backup in the last 7 days",
                VerificationFailureReport.selfTestFinding(findings.get(3)));
    }

    @Test
    void anUntaggedLineStillNamesAComponent() {
        SecurityAuditRunner.Finding untagged = SecurityAuditRunner.findingsIn(OUTPUT).get(4);
        assertEquals("엔진 서버", untagged.getComponent());
        assertEquals("기타", untagged.getItem());
    }

    @Test
    void theSelfTestSummaryGroupsTheItemsByComponent() {
        String summary = VerificationFailureReport.selfTestSummary(
                SecurityAuditRunner.findingsIn(OUTPUT), "timer, 2026-10-06T02:30:11+09:00");
        assertEquals("자체시험 실패 요약 (timer, 2026-10-06T02:30:11+09:00): 실패 4건, 경고 1건"
                + " | 엔진 서버 - 실패: 설정 파일 권한(1), TLS 인증서(2), 기타(1) / 경고: 백업 설정(1)",
                summary);
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
    void theIntegritySummaryCountsByKindAndNamesFilesByComponent() {
        List<IntegrityVerification.Change> changes = new ArrayList<>();
        changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.CHANGED,
                "/etc/ovirt-engine/engine.conf"));
        changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.REMOVED,
                "/usr/share/ovirt-engine/bin/engine-config.sh"));
        changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.ADDED,
                "/usr/share/ovirt-engine/engine.ear/webadmin.war/x.js"));
        assertEquals("무결성 검증 실패 요약 (webadmin): 총 3건 (변경 1, 삭제 1, 추가 1)"
                + " | 엔진 서버 2건: /etc/ovirt-engine/engine.conf(변경), "
                + "/usr/share/ovirt-engine/bin/engine-config.sh(삭제)"
                + " | 클라이언트(WebAdmin) 1건: /usr/share/ovirt-engine/engine.ear/webadmin.war/x.js(추가)",
                VerificationFailureReport.integritySummary(changes, "webadmin"));
        assertTrue(VerificationFailureReport.integrityChange(changes.get(1))
                .startsWith("무결성 검증 실패 [구성요소: 엔진 서버 | 삭제] "));
    }

    @Test
    void aLongListIsCutAndCounted() {
        List<IntegrityVerification.Change> changes = new ArrayList<>();
        for (int i = 0; i < VerificationFailureReport.MAX_NAMED_FILES + 3; i++) {
            changes.add(new IntegrityVerification.Change(IntegrityVerification.Change.Kind.CHANGED, "/etc/f" + i));
        }
        assertTrue(VerificationFailureReport.integritySummary(changes, "").endsWith(" 외 3건"));
    }

    @Test
    void aVerificationThatCouldNotRunSaysSo() {
        assertEquals("무결성 검증 실패 요약 (timer): 검증을 수행하지 못함 "
                + "[구성요소: 엔진 서버 | 항목: 무결성 검사(AIDE)] AIDE exit code 17",
                VerificationFailureReport.integrityNotCarriedOut("timer", 17));
    }
}
