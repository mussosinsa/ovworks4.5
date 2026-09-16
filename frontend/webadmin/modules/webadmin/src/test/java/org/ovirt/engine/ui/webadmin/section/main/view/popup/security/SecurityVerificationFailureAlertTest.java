package org.ovirt.engine.ui.webadmin.section.main.view.popup.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * What the window says when a verification fails. It is read at the moment something has gone
 * wrong, so it has to name the right check, read as Korean, and fit in a window.
 */
class SecurityVerificationFailureAlertTest {

    private static final String SECURITY_AUDIT = "자체 보안 검증"; //$NON-NLS-1$
    private static final String INTEGRITY_CHECK = "무결성 검사"; //$NON-NLS-1$
    private static final String ADVICE = " 실패했습니다. 시스템을 점검해 주세요."; //$NON-NLS-1$
    private static final String TRUNCATION_NOTE = "(자세한 내용은 화면의 오류 내용을 확인하세요)"; //$NON-NLS-1$

    @Test
    void namesTheCheckThatFailedAndWhatToDoAboutIt() {
        String reason = "SELinux is disabled"; //$NON-NLS-1$

        assertEquals(SECURITY_AUDIT + "이" + ADVICE + "\n\n" + reason, //$NON-NLS-1$ //$NON-NLS-2$
                SecurityVerificationFailureAlert.message(SECURITY_AUDIT, reason));
    }

    @Test
    void takesTheParticleTheNameEndsOn() {
        // 검증 ends in a consonant, 검사 ends in a vowel.
        assertEquals(SECURITY_AUDIT + "이", //$NON-NLS-1$
                SecurityVerificationFailureAlert.withSubjectParticle(SECURITY_AUDIT));
        assertEquals(INTEGRITY_CHECK + "가", //$NON-NLS-1$
                SecurityVerificationFailureAlert.withSubjectParticle(INTEGRITY_CHECK));
    }

    @Test
    void saysOnlyWhatItKnowsWhenThereIsNoReason() {
        String expected = INTEGRITY_CHECK + "가" + ADVICE; //$NON-NLS-1$

        assertEquals(expected, SecurityVerificationFailureAlert.message(INTEGRITY_CHECK, "")); //$NON-NLS-1$
        assertEquals(expected, SecurityVerificationFailureAlert.message(INTEGRITY_CHECK, null));
    }

    @Test
    void keepsALongReasonToAWindowfulAndSaysWhereTheRestIs() {
        String shortened = SecurityVerificationFailureAlert.shorten(filler(900));

        assertTrue(shortened.startsWith(filler(SecurityVerificationFailureAlert.DETAIL_LIMIT)));
        assertTrue(shortened.endsWith(TRUNCATION_NOTE));
    }

    @Test
    void leavesAReasonThatAlreadyFitsAlone() {
        String reason = "Security audit failed with exit code: 40"; //$NON-NLS-1$

        assertEquals(reason, SecurityVerificationFailureAlert.shorten(reason));
    }

    private static String filler(int length) {
        char[] characters = new char[length];
        Arrays.fill(characters, 'x');
        return new String(characters);
    }
}
