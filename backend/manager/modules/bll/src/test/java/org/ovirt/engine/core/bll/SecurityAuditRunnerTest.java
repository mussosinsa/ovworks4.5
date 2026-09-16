package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The exit codes are the contract with ovirt-engine-security-verification-runner.sh. Reading one
 * of them as the wrong thing would report an audit that found something as an audit that failed to
 * run, or the other way round.
 */
class SecurityAuditRunnerTest {

    @Test
    void everyCheckPassing() {
        assertEquals(SecurityAuditRunner.Outcome.PASSED, SecurityAuditRunner.outcomeOf(0));
    }

    @Test
    void theAuditRanAndFoundSomething() {
        assertEquals(SecurityAuditRunner.Outcome.FINDINGS, SecurityAuditRunner.outcomeOf(20));
    }

    @Test
    void anotherVerificationHeldTheScriptsOwnLock() {
        assertEquals(SecurityAuditRunner.Outcome.BUSY, SecurityAuditRunner.outcomeOf(75));
    }

    @ParameterizedTest
    @ValueSource(ints = { 1, 40, 64, 127 })
    void anythingElseIsAnAuditThatCouldNotBeRun(int exitCode) {
        assertEquals(SecurityAuditRunner.Outcome.FAILED, SecurityAuditRunner.outcomeOf(exitCode));
    }

    @Test
    void theTallyReadsAsItIsWrittenIntoTheAuditRecord() {
        assertEquals("passed=32, warnings=2, failed=1",
                new SecurityAuditRunner.Summary(32, 2, 1).toString());
    }
}
