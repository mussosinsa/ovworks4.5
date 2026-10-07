package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The checks that did not pass are read back out of what the audit script printed, so that each of
 * them reaches the event list on a line of its own.
 */
class SecurityAuditFindingsTest {

    private static final String ESC = "";

    @Test
    void picksOutTheChecksThatDidNotPass() {
        List<SecurityAuditRunner.Finding> findings = SecurityAuditRunner.findingsIn(String.join("\n",
                "[INFO] Starting security audit",
                "[PASS] engine.conf has secure permissions",
                "[FAIL] SELinux is disabled",
                "[WARN] Certificate expires in 20 days",
                "[PASS] .pgpass has secure permissions"));

        assertEquals(2, findings.size());
        assertEquals(SecurityAuditRunner.Finding.Level.FAILED, findings.get(0).getLevel());
        assertEquals("SELinux is disabled", findings.get(0).getText());
        assertEquals(SecurityAuditRunner.Finding.Level.WARNING, findings.get(1).getLevel());
        assertEquals("Certificate expires in 20 days", findings.get(1).getText());
    }

    @Test
    void readsEveryTaggedItemPassedAndSkippedAsWell() {
        List<SecurityAuditRunner.Finding> findings = SecurityAuditRunner.findingsIn(String.join("\n",
                "[INFO] Checking process ovirt-engine (ovirt-engine.service: enabled)...",
                "[PASS] [ovirt-engine/프로세스 실행 상태] ovirt-engine.service: 실행 중(active, PID 10, 계정 ovirt)",
                "[FAIL] [ovirt-engine/설정 파일] /etc/ovirt-engine/aaa/internal.properties: 기타 사용자 쓰기 권한",
                "[SKIP] [ovirt-provider-ovn/프로세스 실행 상태] ovirt-provider-ovn.service: 설치되지 않음"));

        assertEquals(3, findings.size());
        assertEquals(SecurityAuditRunner.Finding.Level.PASSED, findings.get(0).getLevel());
        assertEquals("ovirt-engine", findings.get(0).getComponent());
        assertEquals("프로세스 실행 상태", findings.get(0).getItem());
        assertEquals(SecurityAuditRunner.Finding.Level.FAILED, findings.get(1).getLevel());
        assertEquals(SecurityAuditRunner.Finding.Level.SKIPPED, findings.get(2).getLevel());
        assertEquals("ovirt-provider-ovn", findings.get(2).getComponent());
        assertEquals(1, SecurityAuditRunner.problemsIn(findings).size());
    }

    @Test
    void readsALineTheScriptColoured() {
        List<SecurityAuditRunner.Finding> findings = SecurityAuditRunner.findingsIn(
                ESC + "[0;31m[FAIL]" + ESC + "[0m Audit log directory not found");

        assertEquals(1, findings.size());
        assertEquals("Audit log directory not found", findings.get(0).getText());
    }

    @Test
    void ignoresTheRunnersOwnLines() {
        List<SecurityAuditRunner.Finding> findings = SecurityAuditRunner.findingsIn(String.join("\n",
                "[2026-09-16T10:54:01+09:00] Security verification started (mode=security, source=startup)",
                "[2026-09-16T10:56:12+09:00] Security audit completed successfully"));

        assertTrue(findings.isEmpty());
    }

    @Test
    void reportsNothingForAnAuditThatPrintedNothing() {
        assertTrue(SecurityAuditRunner.findingsIn("").isEmpty());
        assertTrue(SecurityAuditRunner.findingsIn(null).isEmpty());
    }
}
