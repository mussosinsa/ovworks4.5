package org.ovirt.engine.ui.uicommonweb.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The five mandatory rules, each with a password that satisfies everything except the rule under
 * test, so a failure names the rule that broke.
 */
class PasswordPolicyValidationTest {

    private static final String USER = "hong.gildong"; //$NON-NLS-1$

    private static List<String> check(String password) {
        return PasswordPolicyValidation.violations(password, USER);
    }

    private static boolean rejects(String password) {
        return !check(password).isEmpty();
    }

    @Test
    void shouldAcceptAPasswordThatMeetsEveryRule() {
        assertTrue(check("Kf7#mQx2$Lpv").isEmpty(), check("Kf7#mQx2$Lpv").toString());
    }

    @Test
    void shouldRequireTwelveCharacters() {
        // 11 characters, every other rule satisfied
        assertTrue(rejects("Kf7#mQx2$Lp"));
        assertFalse(rejects("Kf7#mQx2$Lpv"));
    }

    @Test
    void shouldRequireEachCharacterClass() {
        assertTrue(rejects("kf7#mqx2$lpv"), "대문자 없음"); //$NON-NLS-1$
        assertTrue(rejects("KF7#MQX2$LPV"), "소문자 없음"); //$NON-NLS-1$
        assertTrue(rejects("Kf#mQxY$Lpvn"), "숫자 없음"); //$NON-NLS-1$
        assertTrue(rejects("Kf7mQx2Lpvn8"), "특수문자 없음"); //$NON-NLS-1$
    }

    @Test
    void shouldRejectAPasswordEqualToTheUserId() {
        assertTrue(rejects(USER));
        // case does not make it a different identity
        assertTrue(rejects("Hong.Gildong")); //$NON-NLS-1$
        // neither does addressing the account as name@profile
        assertTrue(PasswordPolicyValidation
                .violations("hong.gildong", "hong.gildong@internal") //$NON-NLS-1$ //$NON-NLS-2$
                .contains("패스워드를 사용자 ID와 동일하게 설정할 수 없습니다.")); //$NON-NLS-1$
    }

    @Test
    void shouldRejectRepeatedCharacters() {
        assertTrue(rejects("Kfff#mQx2$Lp"), "동일 문자 3회 연속"); //$NON-NLS-1$
        assertTrue(rejects("Kf7#mQ222$Lp"), "동일 숫자 3회 연속"); //$NON-NLS-1$
        assertTrue(rejects("Kf7#KF7#mQx2"), "동일 패턴 반복"); //$NON-NLS-1$
        // two in a row is still allowed
        assertFalse(rejects("Kff#mQx2$Lpv"));
    }

    @Test
    void shouldRejectSequencesOfFour() {
        assertTrue(rejects("Kabcd#mQx2$L"), "알파벳 연속"); //$NON-NLS-1$
        assertTrue(rejects("K1234#mQx$Lp"), "숫자 연속"); //$NON-NLS-1$
        assertTrue(rejects("Kqwer#mQx2$L"), "키보드 연속"); //$NON-NLS-1$
        assertTrue(rejects("Kasdf#mQx2$L"), "키보드 연속 2행"); //$NON-NLS-1$
        assertTrue(rejects("Kzxcv#mQx2$L"), "키보드 연속 3행"); //$NON-NLS-1$
        assertTrue(rejects("Kdcba#mQx2$L"), "역방향 연속"); //$NON-NLS-1$
        // three in a row is still allowed
        assertFalse(rejects("Kabc#mQx2$Lp"));
    }

    @Test
    void shouldReportEveryViolatedRuleAtOnce() {
        // short, no uppercase, no special, and a sequence
        List<String> reasons = check("abcd12"); //$NON-NLS-1$

        assertEquals(4, reasons.size(), reasons.toString());
    }

    @Test
    void shouldRejectAnAbsentPassword() {
        assertTrue(rejects(null));
        assertTrue(rejects("")); //$NON-NLS-1$
    }

    @Test
    void shouldNotCheckTheUserIdRuleWhenThereIsNoUserId() {
        assertTrue(PasswordPolicyValidation.violations("Kf7#mQx2$Lpv", null).isEmpty()); //$NON-NLS-1$
    }
}
