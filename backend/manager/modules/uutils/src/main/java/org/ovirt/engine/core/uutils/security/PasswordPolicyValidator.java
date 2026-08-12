package org.ovirt.engine.core.uutils.security;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Stateless evaluation of a {@link PasswordPolicy} against a candidate password.
 *
 * <p>All checks are case insensitive where a case sensitive comparison would let a
 * trivially modified password through, i.e. the user id comparison, the repetition
 * check and the sequence check.</p>
 */
public class PasswordPolicyValidator {

    /**
     * Character runs that are considered "sequential". Both directions are rejected, so
     * listing every run once is enough.
     */
    private static final String[] SEQUENCES = {
        "0123456789",
        "abcdefghijklmnopqrstuvwxyz",
        // keyboard rows of a us layout, unshifted and shifted
        "`1234567890-=",
        "qwertyuiop[]\\",
        "asdfghjkl;'",
        "zxcvbnm,./",
        "~!@#$%^&*()_+",
    };

    /** Longest repeated block that is looked for by the pattern repetition check. */
    private static final int MAX_PATTERN_LENGTH = 4;

    private PasswordPolicyValidator() {
    }

    /**
     * Evaluates every enabled rule that can be decided without a password history.
     *
     * @param policy the policy to enforce, never null
     * @param password the candidate password, may be null or empty
     * @param userId the login name of the account the password belongs to, may be null
     * @return every violated rule, an empty list when the password is acceptable
     */
    public static List<PasswordPolicyViolation> validate(PasswordPolicy policy, String password, String userId) {
        List<PasswordPolicyViolation> violations = new ArrayList<>();

        if (password == null || password.isEmpty()) {
            violations.add(new PasswordPolicyViolation(
                    PasswordPolicyViolation.Rule.MIN_LENGTH,
                    String.format("패스워드는 최소 %d자리 이상이어야 합니다.", policy.getMinLength())));
            return violations;
        }

        if (password.length() < policy.getMinLength()) {
            violations.add(new PasswordPolicyViolation(
                    PasswordPolicyViolation.Rule.MIN_LENGTH,
                    String.format("패스워드는 최소 %d자리 이상이어야 합니다.", policy.getMinLength())));
        }

        if (policy.isRequireUppercase() && !password.matches(".*[A-Z].*")) {
            violations.add(new PasswordPolicyViolation(
                    PasswordPolicyViolation.Rule.UPPERCASE,
                    "패스워드에는 영문 대문자가 최소 1개 이상 포함되어야 합니다."));
        }

        if (policy.isRequireLowercase() && !password.matches(".*[a-z].*")) {
            violations.add(new PasswordPolicyViolation(
                    PasswordPolicyViolation.Rule.LOWERCASE,
                    "패스워드에는 영문 소문자가 최소 1개 이상 포함되어야 합니다."));
        }

        if (policy.isRequireDigit() && !password.matches(".*[0-9].*")) {
            violations.add(new PasswordPolicyViolation(
                    PasswordPolicyViolation.Rule.DIGIT,
                    "패스워드에는 숫자가 최소 1개 이상 포함되어야 합니다."));
        }

        if (policy.isRequireSpecial() && !password.matches(".*[^A-Za-z0-9].*")) {
            violations.add(new PasswordPolicyViolation(
                    PasswordPolicyViolation.Rule.SPECIAL,
                    "패스워드에는 특수문자가 최소 1개 이상 포함되어야 합니다."));
        }

        String lowered = password.toLowerCase(Locale.ROOT);

        if (policy.isForbidSameAsUserId() && isSameAsUserId(lowered, userId)) {
            violations.add(new PasswordPolicyViolation(
                    PasswordPolicyViolation.Rule.SAME_AS_USER_ID,
                    "패스워드를 사용자 ID와 동일하게 설정할 수 없습니다."));
        }

        if (policy.isForbidRepeated() && hasRepetition(lowered, policy.getRepeatLimit())) {
            violations.add(new PasswordPolicyViolation(
                    PasswordPolicyViolation.Rule.REPEATED_CHARACTERS,
                    String.format(
                            "패스워드에 동일한 문자를 %d회 이상 반복하거나 동일한 패턴을 반복할 수 없습니다.",
                            policy.getRepeatLimit())));
        }

        if (policy.isForbidSequential() && hasSequence(lowered, policy.getSequenceLength())) {
            violations.add(new PasswordPolicyViolation(
                    PasswordPolicyViolation.Rule.SEQUENTIAL_CHARACTERS,
                    String.format(
                            "패스워드에 알파벳, 숫자 또는 키보드상 연속된 %d자리를 사용할 수 없습니다.",
                            policy.getSequenceLength())));
        }

        return violations;
    }

    /**
     * Evaluates the two reuse rules against a password history.
     *
     * @param policy the policy to enforce, never null
     * @param password the candidate password
     * @param history the password history ordered by change date, most recent first
     * @param now the reference point for the "reused within N months" window
     * @return the violated reuse rule, if any
     */
    public static Optional<PasswordPolicyViolation> validateHistory(
            PasswordPolicy policy,
            String password,
            Collection<PasswordHistoryEntry> history,
            Instant now) {
        if (password == null || history == null || history.isEmpty()) {
            return Optional.empty();
        }

        List<PasswordHistoryEntry> entries = new ArrayList<>(history);
        entries.sort((left, right) -> right.getChangeDate().compareTo(left.getChangeDate()));

        if (policy.isForbidPreviousPassword()) {
            PasswordHistoryEntry previous = entries.get(0);
            if (PasswordHistoryCryptor.matches(password, previous.getEncodedHash())) {
                return Optional.of(new PasswordPolicyViolation(
                        PasswordPolicyViolation.Rule.PREVIOUS_PASSWORD,
                        "직전에 사용한 패스워드는 다시 사용할 수 없습니다."));
            }
        }

        if (policy.isForbidHistoryReuse() && policy.getHistoryMonths() > 0) {
            Instant threshold = now.atZone(ZoneOffset.UTC)
                    .minusMonths(policy.getHistoryMonths())
                    .toInstant()
                    .truncatedTo(ChronoUnit.SECONDS);
            for (PasswordHistoryEntry entry : entries) {
                if (entry.getChangeDate().isBefore(threshold)) {
                    continue;
                }
                if (PasswordHistoryCryptor.matches(password, entry.getEncodedHash())) {
                    return Optional.of(new PasswordPolicyViolation(
                            PasswordPolicyViolation.Rule.PASSWORD_HISTORY,
                            String.format(
                                    "최근 %d개월 이내에 사용한 패스워드는 다시 사용할 수 없습니다.",
                                    policy.getHistoryMonths())));
                }
            }
        }

        return Optional.empty();
    }

    /**
     * @return the messages of the given violations, in the order the rules were evaluated
     */
    public static List<String> toMessages(Collection<PasswordPolicyViolation> violations) {
        if (violations == null || violations.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> messages = new ArrayList<>(violations.size());
        for (PasswordPolicyViolation violation : violations) {
            messages.add(violation.getMessage());
        }
        return messages;
    }

    private static boolean isSameAsUserId(String loweredPassword, String userId) {
        if (userId == null || userId.isEmpty()) {
            return false;
        }
        String loweredUserId = userId.toLowerCase(Locale.ROOT);
        if (loweredPassword.equals(loweredUserId)) {
            return true;
        }
        // an account is commonly addressed as name@profile, the local part alone is the
        // very same identity and must not be accepted either
        int separator = loweredUserId.indexOf('@');
        return separator > 0 && loweredPassword.equals(loweredUserId.substring(0, separator));
    }

    private static boolean hasRepetition(String lowered, int repeatLimit) {
        if (repeatLimit > 1) {
            int run = 1;
            for (int i = 1; i < lowered.length(); i++) {
                run = lowered.charAt(i) == lowered.charAt(i - 1) ? run + 1 : 1;
                if (run >= repeatLimit) {
                    return true;
                }
            }
        }

        // a repeated block such as "abab" or "123123" is as guessable as a repeated character
        for (int length = 2; length <= MAX_PATTERN_LENGTH; length++) {
            for (int i = 0; i + 2 * length <= lowered.length(); i++) {
                if (lowered.regionMatches(i, lowered, i + length, length)) {
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean hasSequence(String lowered, int sequenceLength) {
        if (sequenceLength < 2 || lowered.length() < sequenceLength) {
            return false;
        }
        for (int i = 0; i + sequenceLength <= lowered.length(); i++) {
            String candidate = lowered.substring(i, i + sequenceLength);
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
