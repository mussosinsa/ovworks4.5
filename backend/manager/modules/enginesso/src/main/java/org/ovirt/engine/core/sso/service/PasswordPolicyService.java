package org.ovirt.engine.core.sso.service;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.sso.api.Credentials;
import org.ovirt.engine.core.sso.api.SsoContext;
import org.ovirt.engine.core.sso.db.SsoDao;
import org.ovirt.engine.core.uutils.security.PasswordHistoryCryptor;
import org.ovirt.engine.core.uutils.security.PasswordHistoryEntry;
import org.ovirt.engine.core.uutils.security.PasswordPolicy;
import org.ovirt.engine.core.uutils.security.PasswordPolicyValidator;
import org.ovirt.engine.core.uutils.security.PasswordPolicyViolation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Enforces the engine password policy on the interactive password change, which is the path
 * a user is sent through when the password is expired, i.e. on the first login after an
 * administrator or engine-setup has set the password.
 *
 * <p>Without this the whole policy would depend on whatever the authn extension happens to
 * be configured with, which the engine neither controls nor writes.</p>
 */
public class PasswordPolicyService {

    private static final Logger log = LoggerFactory.getLogger(PasswordPolicyService.class);

    private static final SsoDao SSO_DAO = new SsoDao();

    /** Number of history entries read for the reuse checks and kept by the cleanup. */
    private static final int HISTORY_LIMIT = 32;

    private PasswordPolicyService() {
    }

    /**
     * @return the messages of the rules the new password violates, empty when it is acceptable
     */
    public static List<String> validate(SsoContext ssoContext, Credentials credentials) {
        PasswordPolicy policy = resolve(ssoContext);
        String newPassword = credentials.getNewCredentials();

        List<PasswordPolicyViolation> violations =
                PasswordPolicyValidator.validate(policy, newPassword, credentials.getUsername());

        if (violations.isEmpty() && policy.isHistoryRequired()) {
            Optional<PasswordPolicyViolation> reuse = PasswordPolicyValidator.validateHistory(
                    policy,
                    newPassword,
                    readHistory(principalKey(credentials)),
                    Instant.now());
            reuse.ifPresent(violations::add);
        }

        return PasswordPolicyValidator.toMessages(violations);
    }

    /**
     * Remembers the password that was just set. A failure here must not undo a password that
     * is already in effect, it is logged instead.
     */
    public static void recordPasswordHistory(SsoContext ssoContext, Credentials credentials) {
        PasswordPolicy policy = resolve(ssoContext);
        if (!policy.isHistoryRequired()) {
            return;
        }
        String principal = principalKey(credentials);
        try {
            Instant now = Instant.now();
            SSO_DAO.insertUserPasswordHistory(
                    principal,
                    PasswordHistoryCryptor.hash(credentials.getNewCredentials()),
                    now);
            SSO_DAO.cleanupUserPasswordHistory(
                    principal,
                    now.atZone(ZoneOffset.UTC)
                            .minusMonths(Math.max(policy.getHistoryMonths(), 1))
                            .toInstant(),
                    HISTORY_LIMIT);
        } catch (RuntimeException ex) {
            log.error("Unable to record the password history of '{}': {}", principal, ex.getMessage());
            log.debug("Exception", ex);
        }
    }

    private static List<PasswordHistoryEntry> readHistory(String principal) {
        try {
            return SSO_DAO.getUserPasswordHistory(principal, HISTORY_LIMIT);
        } catch (RuntimeException ex) {
            // a history that can not be read must not silently turn the reuse checks off
            log.error("Unable to read the password history of '{}': {}", principal, ex.getMessage());
            log.debug("Exception", ex);
            throw ex;
        }
    }

    private static String principalKey(Credentials credentials) {
        return PasswordHistoryCryptor.principalKey(credentials.getUsername(), credentials.getProfile());
    }

    private static PasswordPolicy resolve(SsoContext ssoContext) {
        return new PasswordPolicy()
                .setMinLength(getInt(ssoContext, "PasswordPolicyMinLength", PasswordPolicy.DEFAULT_MIN_LENGTH))
                .setRequireUppercase(getBoolean(ssoContext, "PasswordPolicyRequireUppercase", true))
                .setRequireLowercase(getBoolean(ssoContext, "PasswordPolicyRequireLowercase", true))
                .setRequireDigit(getBoolean(ssoContext, "PasswordPolicyRequireDigit", true))
                .setRequireSpecial(getBoolean(ssoContext, "PasswordPolicyRequireSpecial", true))
                .setForbidSameAsUserId(getBoolean(ssoContext, "PasswordPolicyForbidSameAsUserId", true))
                .setForbidRepeated(getBoolean(ssoContext, "PasswordPolicyForbidRepeatedCharacters", true))
                .setRepeatLimit(getInt(ssoContext, "PasswordPolicyRepeatLimit", PasswordPolicy.DEFAULT_REPEAT_LIMIT))
                .setForbidSequential(getBoolean(ssoContext, "PasswordPolicyForbidSequentialCharacters", true))
                .setSequenceLength(
                        getInt(ssoContext, "PasswordPolicySequenceLength", PasswordPolicy.DEFAULT_SEQUENCE_LENGTH))
                .setForbidPreviousPassword(getBoolean(ssoContext, "PasswordPolicyForbidPreviousPassword", true))
                .setForbidHistoryReuse(getBoolean(ssoContext, "PasswordPolicyForbidReuseWithinPeriod", true))
                .setHistoryMonths(
                        getInt(ssoContext, "PasswordPolicyReuseHistoryMonths", PasswordPolicy.DEFAULT_HISTORY_MONTHS));
    }

    private static String getConfigValue(SsoContext ssoContext, String key) {
        String dbValue = null;
        try {
            dbValue = SSO_DAO.getVdcOptionValue(key);
        } catch (Exception ex) {
            log.debug("Unable to read '{}' from vdc_options, fallback to local config", key, ex);
        }
        return StringUtils.defaultIfEmpty(dbValue, ssoContext.getSsoLocalConfig().getProperty(key, true));
    }

    private static int getInt(SsoContext ssoContext, String key, int fallback) {
        String configured = getConfigValue(ssoContext, key);
        if (StringUtils.isBlank(configured)) {
            return fallback;
        }
        try {
            return Integer.parseInt(configured.trim());
        } catch (NumberFormatException ex) {
            log.warn("Invalid {}='{}', fallback to default {}", key, configured, fallback);
            return fallback;
        }
    }

    private static boolean getBoolean(SsoContext ssoContext, String key, boolean fallback) {
        String configured = getConfigValue(ssoContext, key);
        if (StringUtils.isBlank(configured)) {
            return fallback;
        }
        return Boolean.parseBoolean(configured.trim());
    }
}
