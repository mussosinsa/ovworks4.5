package org.ovirt.engine.core.sso.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.function.Function;

final class PasswordSecurityPolicy {

    static final String MIN_LENGTH = "ENGINE_SSO_PASSWORD_MIN_LENGTH"; //$NON-NLS-1$
    static final String REQUIRE_UPPERCASE = "ENGINE_SSO_PASSWORD_REQUIRE_UPPERCASE"; //$NON-NLS-1$
    static final String REQUIRE_LOWERCASE = "ENGINE_SSO_PASSWORD_REQUIRE_LOWERCASE"; //$NON-NLS-1$
    static final String REQUIRE_DIGIT = "ENGINE_SSO_PASSWORD_REQUIRE_DIGIT"; //$NON-NLS-1$
    static final String REQUIRE_SPECIAL = "ENGINE_SSO_PASSWORD_REQUIRE_SPECIAL"; //$NON-NLS-1$
    static final String REJECT_REPEATED = "ENGINE_SSO_PASSWORD_REJECT_REPEATED"; //$NON-NLS-1$
    static final String REJECT_SEQUENTIAL = "ENGINE_SSO_PASSWORD_REJECT_SEQUENTIAL"; //$NON-NLS-1$
    static final String REJECT_PREVIOUS = "ENGINE_SSO_PASSWORD_REJECT_PREVIOUS"; //$NON-NLS-1$

    private static final int DEFAULT_MIN_LENGTH = 12;
    private static final String[] SEQUENCES = {
            "abcdefghijklmnopqrstuvwxyz", //$NON-NLS-1$
            "0123456789", //$NON-NLS-1$
            "qwertyuiop", //$NON-NLS-1$
            "asdfghjkl", //$NON-NLS-1$
            "zxcvbnm" //$NON-NLS-1$
    };

    private PasswordSecurityPolicy() {
    }

    static String validate(String username, String previousPassword, String newPassword,
            Function<String, String> setting) {
        int minimumLength = integerSetting(setting, MIN_LENGTH, DEFAULT_MIN_LENGTH);
        if (newPassword == null || newPassword.length() < minimumLength) {
            return "새 패스워드는 최소 " + minimumLength //$NON-NLS-1$
                    + "자리 이상이어야 합니다."; //$NON-NLS-1$
        }
        if (username != null && username.equalsIgnoreCase(newPassword)) {
            return "새 패스워드는 사용자 ID와 같을 수 없습니다."; //$NON-NLS-1$
        }
        if (enabled(setting, REQUIRE_UPPERCASE) && !containsCharacterBetween(newPassword, 'A', 'Z')) {
            return "새 패스워드에는 영문 대문자가 포함되어야 합니다."; //$NON-NLS-1$
        }
        if (enabled(setting, REQUIRE_LOWERCASE) && !containsCharacterBetween(newPassword, 'a', 'z')) {
            return "새 패스워드에는 영문 소문자가 포함되어야 합니다."; //$NON-NLS-1$
        }
        if (enabled(setting, REQUIRE_DIGIT) && !containsCharacterBetween(newPassword, '0', '9')) {
            return "새 패스워드에는 숫자가 포함되어야 합니다."; //$NON-NLS-1$
        }
        if (enabled(setting, REQUIRE_SPECIAL) && newPassword.chars().allMatch(Character::isLetterOrDigit)) {
            return "새 패스워드에는 특수문자가 포함되어야 합니다."; //$NON-NLS-1$
        }
        if (enabled(setting, REJECT_REPEATED) && hasRepeatedPattern(newPassword)) {
            return "새 패스워드에는 반복되는 문자 또는 패턴을 사용할 수 없습니다."; //$NON-NLS-1$
        }
        if (enabled(setting, REJECT_SEQUENTIAL) && hasFourCharacterSequence(newPassword)) {
            return "새 패스워드에는 연속된 영문자, 숫자 또는 키보드 문자를 4자리 이상 사용할 수 없습니다."; //$NON-NLS-1$
        }
        if (enabled(setting, REJECT_PREVIOUS) && passwordsEqual(previousPassword, newPassword)) {
            return "직전 패스워드는 다시 사용할 수 없습니다."; //$NON-NLS-1$
        }
        return null;
    }

    private static boolean enabled(Function<String, String> setting, String name) {
        String configured = setting.apply(name);
        return configured == null || configured.isEmpty() || Boolean.parseBoolean(configured);
    }

    private static int integerSetting(Function<String, String> setting, String name, int defaultValue) {
        String configured = setting.apply(name);
        try {
            int value = Integer.parseInt(configured);
            return Math.max(value, defaultValue);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static boolean hasRepeatedPattern(String password) {
        for (int index = 2; index < password.length(); index++) {
            if (password.charAt(index) == password.charAt(index - 1)
                    && password.charAt(index) == password.charAt(index - 2)) {
                return true;
            }
        }
        for (int size = 2; size <= password.length() / 2; size++) {
            for (int index = 0; index + size * 2 <= password.length(); index++) {
                if (password.regionMatches(index, password, index + size, size)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean containsCharacterBetween(String value, char lower, char upper) {
        return value.chars().anyMatch(character -> character >= lower && character <= upper);
    }

    private static boolean hasFourCharacterSequence(String password) {
        String normalized = password.toLowerCase(Locale.ROOT);
        for (String sequence : SEQUENCES) {
            for (int index = 0; index <= sequence.length() - 4; index++) {
                String token = sequence.substring(index, index + 4);
                if (normalized.contains(token) || normalized.contains(new StringBuilder(token).reverse())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean passwordsEqual(String previousPassword, String newPassword) {
        return previousPassword != null && MessageDigest.isEqual(
                previousPassword.getBytes(StandardCharsets.UTF_8),
                newPassword.getBytes(StandardCharsets.UTF_8));
    }
}
