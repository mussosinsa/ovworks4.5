package org.ovirt.engine.ui.webadmin.section.main.view.popup.security;

/**
 * What the administrator is told when a verification on the security settings screen fails.
 *
 * <p>The wording lives away from the screen that shows it so that it can be read back and checked:
 * the screen itself cannot be built outside a browser, and a message read at the moment something
 * has gone wrong is worth being sure of.</p>
 */
public final class SecurityVerificationFailureAlert {

    /** How much of the reason the window carries before it stops being one a person reads. */
    static final int DETAIL_LIMIT = 500;

    /** The block of composed Hangul syllables, and how many finals one cycles through. */
    private static final char HANGUL_FIRST = '가';
    private static final char HANGUL_LAST = '힣';
    private static final int HANGUL_FINALS = 28;

    private SecurityVerificationFailureAlert() {
    }

    /**
     * What the window says: which verification failed, what to do, and as much of the reason as
     * reads in a window - the rest stays under the button, where it is not cut off.
     *
     * @param checkName the verification as the screen names it
     * @param details what the action said about the failure, may be null or empty
     */
    public static String message(String checkName, String details) {
        StringBuilder message = new StringBuilder()
                .append(withSubjectParticle(checkName))
                .append(" 실패했습니다. 시스템을 점검해 주세요."); //$NON-NLS-1$
        String reason = details == null ? "" : details.trim(); //$NON-NLS-1$
        if (!reason.isEmpty()) {
            message.append("\n\n").append(shorten(reason)); //$NON-NLS-1$
        }
        return message.toString();
    }

    /**
     * Adds the subject particle the name takes.
     *
     * <p>Korean picks it by the sound the name ends on: a syllable ending in a consonant takes one
     * and a syllable ending in a vowel takes the other, so "자체 보안 검증이" but "무결성 검사가".
     * One particle for both reads as a mistake in whichever name it is wrong for.</p>
     */
    static String withSubjectParticle(String name) {
        if (name == null || name.isEmpty()) {
            return ""; //$NON-NLS-1$
        }
        char last = name.charAt(name.length() - 1);
        boolean endsInConsonant = last >= HANGUL_FIRST && last <= HANGUL_LAST
                && (last - HANGUL_FIRST) % HANGUL_FINALS != 0;
        return name + (endsInConsonant ? "이" : "가"); //$NON-NLS-1$ //$NON-NLS-2$
    }

    /** Keeps the window readable; the whole reason is on the screen behind it either way. */
    static String shorten(String reason) {
        if (reason.length() <= DETAIL_LIMIT) {
            return reason;
        }
        return reason.substring(0, DETAIL_LIMIT).trim()
                + "\n... (자세한 내용은 화면의 오류 내용을 확인하세요)"; //$NON-NLS-1$
    }
}
