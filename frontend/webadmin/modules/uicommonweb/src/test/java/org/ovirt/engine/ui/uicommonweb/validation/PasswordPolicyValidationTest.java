package org.ovirt.engine.ui.uicommonweb.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The five mandatory rules. Each password below satisfies every rule except the one its name
 * gives, so a failure names the rule that broke.
 */
class PasswordPolicyValidationTest {

    private static final String USER = "hong.gildong"; //$NON-NLS-1$
    private static final String USER_WITH_PROFILE = "hong.gildong@internal"; //$NON-NLS-1$
    private static final String SAME_AS_USER_MESSAGE =
            "패스워드를 사용자 ID와 동일하게 설정할 수 없습니다."; //$NON-NLS-1$

    private static final String ACCEPTED = "Kf7#mQx2$Lpv"; //$NON-NLS-1$

    private static final String ELEVEN_CHARACTERS = "Kf7#mQx2$Lp"; //$NON-NLS-1$
    private static final String NO_UPPERCASE = "kf7#mqx2$lpv"; //$NON-NLS-1$
    private static final String NO_LOWERCASE = "KF7#MQX2$LPV"; //$NON-NLS-1$
    private static final String NO_DIGIT = "Kf#mQxY$Lpvn"; //$NON-NLS-1$
    private static final String NO_SPECIAL = "Kf7mQx2Lpvn8"; //$NON-NLS-1$
    private static final String USER_ID_IN_MIXED_CASE = "Hong.Gildong"; //$NON-NLS-1$

    private static final String THREE_SAME_LETTERS = "Kfff#mQx2$Lp"; //$NON-NLS-1$
    private static final String THREE_SAME_DIGITS = "Kf7#mQ222$Lp"; //$NON-NLS-1$
    private static final String REPEATED_BLOCK = "Kf7#KF7#mQx2"; //$NON-NLS-1$
    private static final String TWO_SAME_LETTERS = "Kff#mQx2$Lpv"; //$NON-NLS-1$

    private static final String FOUR_LETTERS_IN_ORDER = "Kabcd#mQx2$L"; //$NON-NLS-1$
    private static final String FOUR_DIGITS_IN_ORDER = "K1234#mQx$Lp"; //$NON-NLS-1$
    private static final String KEYBOARD_TOP_ROW = "Kqwer#mQx2$L"; //$NON-NLS-1$
    private static final String KEYBOARD_HOME_ROW = "Kasdf#mQx2$L"; //$NON-NLS-1$
    private static final String KEYBOARD_BOTTOM_ROW = "Kzxcv#mQx2$L"; //$NON-NLS-1$
    private static final String FOUR_LETTERS_REVERSED = "Kdcba#mQx2$L"; //$NON-NLS-1$
    private static final String THREE_LETTERS_IN_ORDER = "Kabc#mQx2$Lp"; //$NON-NLS-1$

    /** Too short, no uppercase, no special character, and a run of four. */
    private static final String BREAKS_FOUR_RULES = "abcd12"; //$NON-NLS-1$

    private static final String EMPTY = ""; //$NON-NLS-1$

    private static List<String> check(String password) {
        return PasswordPolicyValidation.violations(password, USER);
    }

    private static boolean rejects(String password) {
        return !check(password).isEmpty();
    }

    @Test
    void shouldAcceptAPasswordThatMeetsEveryRule() {
        assertTrue(check(ACCEPTED).isEmpty(), check(ACCEPTED).toString());
    }

    @Test
    void shouldRequireTwelveCharacters() {
        assertTrue(rejects(ELEVEN_CHARACTERS));
        assertFalse(rejects(ACCEPTED));
    }

    @Test
    void shouldRequireEachCharacterClass() {
        assertTrue(rejects(NO_UPPERCASE));
        assertTrue(rejects(NO_LOWERCASE));
        assertTrue(rejects(NO_DIGIT));
        assertTrue(rejects(NO_SPECIAL));
    }

    @Test
    void shouldRejectAPasswordEqualToTheUserId() {
        assertTrue(rejects(USER));
        // case does not make it a different identity
        assertTrue(rejects(USER_ID_IN_MIXED_CASE));
        // neither does addressing the account as name@profile
        assertTrue(PasswordPolicyValidation.violations(USER, USER_WITH_PROFILE)
                .contains(SAME_AS_USER_MESSAGE));
    }

    @Test
    void shouldRejectRepeatedCharacters() {
        assertTrue(rejects(THREE_SAME_LETTERS));
        assertTrue(rejects(THREE_SAME_DIGITS));
        assertTrue(rejects(REPEATED_BLOCK));
        // two in a row is still allowed
        assertFalse(rejects(TWO_SAME_LETTERS));
    }

    @Test
    void shouldRejectSequencesOfFour() {
        assertTrue(rejects(FOUR_LETTERS_IN_ORDER));
        assertTrue(rejects(FOUR_DIGITS_IN_ORDER));
        assertTrue(rejects(KEYBOARD_TOP_ROW));
        assertTrue(rejects(KEYBOARD_HOME_ROW));
        assertTrue(rejects(KEYBOARD_BOTTOM_ROW));
        assertTrue(rejects(FOUR_LETTERS_REVERSED));
        // three in a row is still allowed
        assertFalse(rejects(THREE_LETTERS_IN_ORDER));
    }

    @Test
    void shouldReportEveryViolatedRuleAtOnce() {
        List<String> reasons = check(BREAKS_FOUR_RULES);

        assertEquals(4, reasons.size(), reasons.toString());
    }

    @Test
    void shouldRejectAnAbsentPassword() {
        assertTrue(rejects(null));
        assertTrue(rejects(EMPTY));
    }

    @Test
    void shouldNotCheckTheUserIdRuleWhenThereIsNoUserId() {
        assertTrue(PasswordPolicyValidation.violations(ACCEPTED, null).isEmpty());
    }
}
