package org.ovirt.engine.core.bll.aaa;

import java.util.Optional;

import org.ovirt.engine.core.uutils.security.LoginInputPolicy;

/**
 * Holds a local user's first and last name to the length the login page holds the login name and
 * the password to ({@link LoginInputPolicy#MAX_LENGTH}, 20 characters).
 *
 * <p>The login name and the password are already checked against that limit, by LoginInputPolicy
 * and by the password policy. The names were not checked at all - not when the account was added,
 * and not when it was edited, where nothing was validated - so the dialog accepted any length.</p>
 */
final class LocalUserNameLength {

    private LocalUserNameLength() {
    }

    /** @return the message for the first name that is too long, or empty when both fit */
    static Optional<String> check(String firstName, String lastName) {
        if (tooLong(firstName)) {
            return Optional.of(message("이름")); //$NON-NLS-1$
        }
        if (tooLong(lastName)) {
            return Optional.of(message("성")); //$NON-NLS-1$
        }
        return Optional.empty();
    }

    private static boolean tooLong(String value) {
        return value != null && value.trim().length() > LoginInputPolicy.MAX_LENGTH;
    }

    private static String message(String field) {
        return String.format("%s은(는) 최대 %d자까지 입력할 수 있습니다.", field, LoginInputPolicy.MAX_LENGTH); //$NON-NLS-1$
    }
}
