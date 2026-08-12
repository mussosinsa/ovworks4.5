package org.ovirt.engine.core.uutils.security;

/**
 * A single password policy rule that the candidate password failed, together with the
 * message that is presented to the end user.
 */
public class PasswordPolicyViolation {

    public enum Rule {
        MIN_LENGTH,
        UPPERCASE,
        LOWERCASE,
        DIGIT,
        SPECIAL,
        SAME_AS_USER_ID,
        REPEATED_CHARACTERS,
        SEQUENTIAL_CHARACTERS,
        PREVIOUS_PASSWORD,
        PASSWORD_HISTORY
    }

    private final Rule rule;
    private final String message;

    public PasswordPolicyViolation(Rule rule, String message) {
        this.rule = rule;
        this.message = message;
    }

    public Rule getRule() {
        return rule;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return rule + ": " + message;
    }
}
