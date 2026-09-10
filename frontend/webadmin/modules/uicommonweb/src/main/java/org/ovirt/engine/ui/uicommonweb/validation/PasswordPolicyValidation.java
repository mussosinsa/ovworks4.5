package org.ovirt.engine.ui.uicommonweb.validation;

import java.util.ArrayList;
import java.util.List;

/**
 * Client side check of the password policy, so that a rejected password is reported while the
 * dialog is still open instead of after a round trip.
 *
 * <p>The engine remains the authority: {@code PasswordPolicyValidator} in the uutils module runs
 * the same rules plus the configurable limits and the reuse history, and rejects anything this
 * lets through. That validator cannot be shared here because it is not translatable to
 * JavaScript, so the mandatory rules are mirrored - keep the two in step when either changes.</p>
 *
 * <p>Every screen that sets a password uses this one class, so the rules cannot differ from one
 * dialog to the next.</p>
 */
public class PasswordPolicyValidation implements IValidation {

    /** Mirrors {@code PasswordPolicy.DEFAULT_MIN_LENGTH}. */
    public static final int MIN_LENGTH = 12;

    /** Mirrors {@code PasswordPolicy.DEFAULT_REPEAT_LIMIT}: the run length that is rejected. */
    public static final int REPEAT_LIMIT = 3;

    /** Mirrors {@code PasswordPolicy.DEFAULT_SEQUENCE_LENGTH}. */
    public static final int SEQUENCE_LENGTH = 4;

    /** Longest repeated block the pattern check looks for, as in the engine side validator. */
    private static final int MAX_PATTERN_LENGTH = 4;

    /**
     * Runs that count as sequential. Both directions are rejected, so each run is listed once.
     * Mirrors the table in the engine side validator.
     */
    private static final String[] SEQUENCES = {
        "0123456789", //$NON-NLS-1$
        "abcdefghijklmnopqrstuvwxyz", //$NON-NLS-1$
        // keyboard rows of a us layout, unshifted and shifted
        "`1234567890-=", //$NON-NLS-1$
        "qwertyuiop[]\\", //$NON-NLS-1$
        "asdfghjkl;'", //$NON-NLS-1$
        "zxcvbnm,./", //$NON-NLS-1$
        "~!@#$%^&*()_+", //$NON-NLS-1$
    };

    private final String userId;

    /**
     * @param userId the login name the password is being set for, used by the "must not equal the
     *        user id" rule. May be null, in which case that rule is not evaluated.
     */
    public PasswordPolicyValidation(String userId) {
        this.userId = userId;
    }

    @Override
    public ValidationResult validate(Object value) {
        String password = value == null ? null : value.toString();
        List<String> reasons = violations(password, userId);
        return reasons.isEmpty() ? ValidationResult.ok() : new ValidationResult(false, reasons);
    }

    /**
     * @return one message per violated rule, in the order the rules are listed to the user; empty
     *         when the password is acceptable
     */
    public static List<String> violations(String password, String userId) {
        List<String> reasons = new ArrayList<>();

        if (password == null || password.isEmpty()) {
            reasons.add(minLengthMessage());
            return reasons;
        }

        if (password.length() < MIN_LENGTH) {
            reasons.add(minLengthMessage());
        }
        if (!password.matches(".*[A-Z].*")) { //$NON-NLS-1$
            reasons.add("패스워드에는 영문 대문자가 최소 1개 이상 포함되어야 합니다."); //$NON-NLS-1$
        }
        if (!password.matches(".*[a-z].*")) { //$NON-NLS-1$
            reasons.add("패스워드에는 영문 소문자가 최소 1개 이상 포함되어야 합니다."); //$NON-NLS-1$
        }
        if (!password.matches(".*[0-9].*")) { //$NON-NLS-1$
            reasons.add("패스워드에는 숫자가 최소 1개 이상 포함되어야 합니다."); //$NON-NLS-1$
        }
        if (!password.matches(".*[^A-Za-z0-9].*")) { //$NON-NLS-1$
            reasons.add("패스워드에는 특수문자가 최소 1개 이상 포함되어야 합니다."); //$NON-NLS-1$
        }

        String lowered = password.toLowerCase();

        if (isSameAsUserId(lowered, userId)) {
            reasons.add("패스워드를 사용자 ID와 동일하게 설정할 수 없습니다."); //$NON-NLS-1$
        }
        if (hasRepetition(lowered)) {
            reasons.add("패스워드에 동일한 문자를 " + REPEAT_LIMIT //$NON-NLS-1$
                    + "회 이상 반복하거나 동일한 패턴을 반복할 수 없습니다."); //$NON-NLS-1$
        }
        if (hasSequence(lowered)) {
            reasons.add("패스워드에 알파벳, 숫자 또는 키보드상 연속된 " + SEQUENCE_LENGTH //$NON-NLS-1$
                    + "자리를 사용할 수 없습니다."); //$NON-NLS-1$
        }

        return reasons;
    }

    private static String minLengthMessage() {
        return "패스워드는 최소 " + MIN_LENGTH + "자리 이상이어야 합니다."; //$NON-NLS-1$ //$NON-NLS-2$
    }

    private static boolean isSameAsUserId(String loweredPassword, String userId) {
        if (userId == null || userId.isEmpty()) {
            return false;
        }
        String loweredUserId = userId.toLowerCase();
        if (loweredPassword.equals(loweredUserId)) {
            return true;
        }
        // an account is commonly addressed as name@profile, the local part alone is the very same
        // identity and must not be accepted either
        int separator = loweredUserId.indexOf('@');
        return separator > 0 && loweredPassword.equals(loweredUserId.substring(0, separator));
    }

    private static boolean hasRepetition(String lowered) {
        int run = 1;
        for (int i = 1; i < lowered.length(); i++) {
            run = lowered.charAt(i) == lowered.charAt(i - 1) ? run + 1 : 1;
            if (run >= REPEAT_LIMIT) {
                return true;
            }
        }

        // a repeated block such as "abab" or "123123" is as guessable as a repeated character
        for (int length = 2; length <= MAX_PATTERN_LENGTH; length++) {
            for (int i = 0; i + 2 * length <= lowered.length(); i++) {
                if (lowered.substring(i, i + length).equals(lowered.substring(i + length, i + 2 * length))) {
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean hasSequence(String lowered) {
        if (lowered.length() < SEQUENCE_LENGTH) {
            return false;
        }
        for (int i = 0; i + SEQUENCE_LENGTH <= lowered.length(); i++) {
            String candidate = lowered.substring(i, i + SEQUENCE_LENGTH);
            String reversed = new StringBuilder(candidate).reverse().toString();
            for (String sequence : SEQUENCES) {
                if (sequence.contains(candidate) || sequence.contains(reversed)) {
                    return true;
                }
            }
        }
        return false;
    }
}
