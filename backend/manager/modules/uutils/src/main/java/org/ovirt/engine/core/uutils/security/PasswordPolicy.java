package org.ovirt.engine.core.uutils.security;

/**
 * Password policy definition shared by every path that sets or changes a password:
 * engine-setup, the administrative password reset and the interactive (self service)
 * password change performed on first login.
 *
 * <p>The mandatory part of the policy is the minimum length and the character class
 * requirements. Every single check can still be turned off through configuration so
 * that a deployment may relax the policy without patching the code.</p>
 */
public class PasswordPolicy {

    public static final int DEFAULT_MIN_LENGTH = 12;
    public static final int DEFAULT_REPEAT_LIMIT = 3;
    public static final int DEFAULT_SEQUENCE_LENGTH = 4;
    public static final int DEFAULT_HISTORY_MONTHS = 3;

    private int minLength = DEFAULT_MIN_LENGTH;

    private boolean requireUppercase = true;
    private boolean requireLowercase = true;
    private boolean requireDigit = true;
    private boolean requireSpecial = true;

    private boolean forbidSameAsUserId = true;

    private boolean forbidRepeated = true;
    private int repeatLimit = DEFAULT_REPEAT_LIMIT;

    private boolean forbidSequential = true;
    private int sequenceLength = DEFAULT_SEQUENCE_LENGTH;

    private boolean forbidPreviousPassword = true;
    private boolean forbidHistoryReuse = true;
    private int historyMonths = DEFAULT_HISTORY_MONTHS;

    public int getMinLength() {
        return minLength;
    }

    public PasswordPolicy setMinLength(int minLength) {
        this.minLength = minLength;
        return this;
    }

    public boolean isRequireUppercase() {
        return requireUppercase;
    }

    public PasswordPolicy setRequireUppercase(boolean requireUppercase) {
        this.requireUppercase = requireUppercase;
        return this;
    }

    public boolean isRequireLowercase() {
        return requireLowercase;
    }

    public PasswordPolicy setRequireLowercase(boolean requireLowercase) {
        this.requireLowercase = requireLowercase;
        return this;
    }

    public boolean isRequireDigit() {
        return requireDigit;
    }

    public PasswordPolicy setRequireDigit(boolean requireDigit) {
        this.requireDigit = requireDigit;
        return this;
    }

    public boolean isRequireSpecial() {
        return requireSpecial;
    }

    public PasswordPolicy setRequireSpecial(boolean requireSpecial) {
        this.requireSpecial = requireSpecial;
        return this;
    }

    public boolean isForbidSameAsUserId() {
        return forbidSameAsUserId;
    }

    public PasswordPolicy setForbidSameAsUserId(boolean forbidSameAsUserId) {
        this.forbidSameAsUserId = forbidSameAsUserId;
        return this;
    }

    public boolean isForbidRepeated() {
        return forbidRepeated;
    }

    public PasswordPolicy setForbidRepeated(boolean forbidRepeated) {
        this.forbidRepeated = forbidRepeated;
        return this;
    }

    public int getRepeatLimit() {
        return repeatLimit;
    }

    public PasswordPolicy setRepeatLimit(int repeatLimit) {
        this.repeatLimit = repeatLimit;
        return this;
    }

    public boolean isForbidSequential() {
        return forbidSequential;
    }

    public PasswordPolicy setForbidSequential(boolean forbidSequential) {
        this.forbidSequential = forbidSequential;
        return this;
    }

    public int getSequenceLength() {
        return sequenceLength;
    }

    public PasswordPolicy setSequenceLength(int sequenceLength) {
        this.sequenceLength = sequenceLength;
        return this;
    }

    public boolean isForbidPreviousPassword() {
        return forbidPreviousPassword;
    }

    public PasswordPolicy setForbidPreviousPassword(boolean forbidPreviousPassword) {
        this.forbidPreviousPassword = forbidPreviousPassword;
        return this;
    }

    public boolean isForbidHistoryReuse() {
        return forbidHistoryReuse;
    }

    public PasswordPolicy setForbidHistoryReuse(boolean forbidHistoryReuse) {
        this.forbidHistoryReuse = forbidHistoryReuse;
        return this;
    }

    public int getHistoryMonths() {
        return historyMonths;
    }

    public PasswordPolicy setHistoryMonths(int historyMonths) {
        this.historyMonths = historyMonths;
        return this;
    }

    /**
     * @return true when either of the two reuse checks is enabled, meaning the caller has to
     *         keep a password history in order to enforce the policy
     */
    public boolean isHistoryRequired() {
        return forbidPreviousPassword || forbidHistoryReuse && historyMonths > 0;
    }
}
