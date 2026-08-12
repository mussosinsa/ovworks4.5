package org.ovirt.engine.core.bll.aaa;

import org.ovirt.engine.core.common.config.Config;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.uutils.security.PasswordPolicy;

/**
 * Builds the {@link PasswordPolicy} that the engine enforces, from the engine configuration.
 *
 * <p>Every check is configurable so that a deployment can relax the policy through
 * {@code engine-config} instead of a code change. The values are read on each call, the
 * options are reloadable.</p>
 */
public class PasswordPolicyResolver {

    private PasswordPolicyResolver() {
    }

    public static PasswordPolicy resolve() {
        return new PasswordPolicy()
                .setMinLength(Config.<Integer> getValue(ConfigValues.PasswordPolicyMinLength))
                .setRequireUppercase(Config.<Boolean> getValue(ConfigValues.PasswordPolicyRequireUppercase))
                .setRequireLowercase(Config.<Boolean> getValue(ConfigValues.PasswordPolicyRequireLowercase))
                .setRequireDigit(Config.<Boolean> getValue(ConfigValues.PasswordPolicyRequireDigit))
                .setRequireSpecial(Config.<Boolean> getValue(ConfigValues.PasswordPolicyRequireSpecial))
                .setForbidSameAsUserId(Config.<Boolean> getValue(ConfigValues.PasswordPolicyForbidSameAsUserId))
                .setForbidRepeated(Config.<Boolean> getValue(ConfigValues.PasswordPolicyForbidRepeatedCharacters))
                .setRepeatLimit(Config.<Integer> getValue(ConfigValues.PasswordPolicyRepeatLimit))
                .setForbidSequential(Config.<Boolean> getValue(ConfigValues.PasswordPolicyForbidSequentialCharacters))
                .setSequenceLength(Config.<Integer> getValue(ConfigValues.PasswordPolicySequenceLength))
                .setForbidPreviousPassword(
                        Config.<Boolean> getValue(ConfigValues.PasswordPolicyForbidPreviousPassword))
                .setForbidHistoryReuse(Config.<Boolean> getValue(ConfigValues.PasswordPolicyForbidReuseWithinPeriod))
                .setHistoryMonths(Config.<Integer> getValue(ConfigValues.PasswordPolicyReuseHistoryMonths));
    }

    public static boolean isForceChangeOnFirstLogin() {
        return Config.<Boolean> getValue(ConfigValues.PasswordPolicyForceChangeOnFirstLogin);
    }
}
