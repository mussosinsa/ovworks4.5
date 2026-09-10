package org.ovirt.engine.core.bll.aaa;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.ovirt.engine.core.common.businessentities.aaa.UserPasswordHistoryEntry;
import org.ovirt.engine.core.dao.UserPasswordHistoryDao;
import org.ovirt.engine.core.uutils.security.PasswordHistoryCryptor;
import org.ovirt.engine.core.uutils.security.PasswordHistoryEntry;
import org.ovirt.engine.core.uutils.security.PasswordPolicy;
import org.ovirt.engine.core.uutils.security.PasswordPolicyValidator;
import org.ovirt.engine.core.uutils.security.PasswordPolicyViolation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The password history behind the two reuse rules: a password must differ from the one it
 * replaces, and from every password used within the configured number of months.
 *
 * <p>Both rules only work when every path that sets a password records what it set. Reading and
 * writing the history therefore lives here rather than in one command, so that adding a local
 * user and resetting a password keep the same history and cannot disagree about what "the
 * previous password" was.</p>
 */
public class UserPasswordHistoryStore {

    /** Entries read for the reuse checks, and the number the cleanup keeps per account. */
    public static final int HISTORY_LIMIT = 32;

    private static final Logger log = LoggerFactory.getLogger(UserPasswordHistoryStore.class);

    private UserPasswordHistoryStore() {
    }

    /**
     * @return the key an account's history is filed under, the normalized {@code name@realm}
     */
    public static String principalKey(String loginName, String domain) {
        return PasswordHistoryCryptor.principalKey(loginName, domain);
    }

    /**
     * Checks the candidate password against the account's history.
     *
     * @return the violated reuse rule, or empty when the password may be used - which is also
     *         the answer when neither reuse rule is enabled, in which case no history is read
     */
    public static Optional<PasswordPolicyViolation> checkReuse(
            UserPasswordHistoryDao dao,
            PasswordPolicy policy,
            String principal,
            String password) {
        if (!policy.isHistoryRequired()) {
            return Optional.empty();
        }
        return PasswordPolicyValidator.validateHistory(policy, password, read(dao, principal), Instant.now());
    }

    /**
     * Remembers a password that has just been set, so the reuse rules can see it later, and drops
     * the entries that are past both the retention period and the entry limit.
     *
     * <p>A failure here must not undo a password that is already in effect, so it is logged and
     * swallowed.</p>
     */
    public static void record(
            UserPasswordHistoryDao dao,
            PasswordPolicy policy,
            String principal,
            String password) {
        if (!policy.isHistoryRequired()) {
            return;
        }
        try {
            dao.save(new UserPasswordHistoryEntry(
                    principal,
                    PasswordHistoryCryptor.hash(password),
                    new Date()));
            dao.cleanup(
                    principal,
                    Date.from(ZonedDateTime.now().minusMonths(Math.max(policy.getHistoryMonths(), 1)).toInstant()),
                    HISTORY_LIMIT);
        } catch (RuntimeException ex) {
            log.error("Unable to record the password history of '{}': {}", principal, ex.getMessage());
            log.debug("Exception", ex);
        }
    }

    private static List<PasswordHistoryEntry> read(UserPasswordHistoryDao dao, String principal) {
        List<PasswordHistoryEntry> history = new ArrayList<>();
        for (UserPasswordHistoryEntry entry : dao.getByPrincipal(principal, HISTORY_LIMIT)) {
            if (entry.getPasswordHash() != null && entry.getChangeDate() != null) {
                history.add(new PasswordHistoryEntry(entry.getPasswordHash(), entry.getChangeDate().toInstant()));
            }
        }
        return history;
    }
}
