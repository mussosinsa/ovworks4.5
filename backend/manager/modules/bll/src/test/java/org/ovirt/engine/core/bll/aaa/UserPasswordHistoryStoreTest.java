package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.common.businessentities.aaa.UserPasswordHistoryEntry;
import org.ovirt.engine.core.dao.UserPasswordHistoryDao;
import org.ovirt.engine.core.uutils.security.PasswordHistoryCryptor;
import org.ovirt.engine.core.uutils.security.PasswordPolicy;
import org.ovirt.engine.core.uutils.security.PasswordPolicyViolation;

/**
 * The two reuse rules, over the history the engine keeps: a password may not be the one it
 * replaces, and may not be one used within the retention period.
 */
class UserPasswordHistoryStoreTest {

    private static final String PRINCIPAL = "user02@internal"; //$NON-NLS-1$

    private static final String CURRENT = "Kf7#mQx2$Lpv"; //$NON-NLS-1$
    private static final String OLDER = "Rt4@nWy8%Zbk"; //$NON-NLS-1$
    private static final String LONG_RETIRED = "Hs2!vJd6&Xqm"; //$NON-NLS-1$
    private static final String NEVER_USED = "Bp9^cLg3*Nrw"; //$NON-NLS-1$

    private final FakeDao dao = new FakeDao();

    private static PasswordPolicy policy() {
        return new PasswordPolicy();
    }

    private Optional<PasswordPolicyViolation> check(String password) {
        return UserPasswordHistoryStore.checkReuse(dao, policy(), PRINCIPAL, password);
    }

    private void record(String password, int daysAgo) {
        dao.entries.add(new UserPasswordHistoryEntry(
                PRINCIPAL, PasswordHistoryCryptor.hash(password), daysAgo(daysAgo)));
    }

    private static Date daysAgo(int days) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_MONTH, -days);
        return calendar.getTime();
    }

    @Test
    void rejectsThePasswordItWouldReplace() {
        record(CURRENT, 1);

        Optional<PasswordPolicyViolation> violation = check(CURRENT);

        assertTrue(violation.isPresent());
        assertEquals(PasswordPolicyViolation.Rule.PREVIOUS_PASSWORD, violation.get().getRule());
    }

    @Test
    void rejectsAPasswordUsedWithinTheRetentionPeriod() {
        record(CURRENT, 1);
        record(OLDER, 40);

        Optional<PasswordPolicyViolation> violation = check(OLDER);

        assertTrue(violation.isPresent());
        assertEquals(PasswordPolicyViolation.Rule.PASSWORD_HISTORY, violation.get().getRule());
    }

    @Test
    void acceptsAPasswordThatFellOutOfTheRetentionPeriod() {
        record(CURRENT, 1);
        // the default retention is three months
        record(LONG_RETIRED, 200);

        assertFalse(check(LONG_RETIRED).isPresent());
    }

    @Test
    void acceptsAPasswordThatWasNeverUsed() {
        record(CURRENT, 1);
        record(OLDER, 40);

        assertFalse(check(NEVER_USED).isPresent());
    }

    @Test
    void readsNoHistoryWhenNeitherReuseRuleIsEnabled() {
        record(CURRENT, 1);
        PasswordPolicy relaxed = policy().setForbidPreviousPassword(false).setForbidHistoryReuse(false);

        assertFalse(UserPasswordHistoryStore.checkReuse(dao, relaxed, PRINCIPAL, CURRENT).isPresent());
        assertEquals(0, dao.reads, "the history should not be read when no rule needs it"); //$NON-NLS-1$
    }

    @Test
    void recordsWhatWasSetSoTheNextChangeCanBeCheckedAgainstIt() {
        UserPasswordHistoryStore.record(dao, policy(), PRINCIPAL, CURRENT);

        assertTrue(check(CURRENT).isPresent(), "the recorded password should now be refused"); //$NON-NLS-1$
    }

    @Test
    void recordsNothingWhenNeitherReuseRuleIsEnabled() {
        PasswordPolicy relaxed = policy().setForbidPreviousPassword(false).setForbidHistoryReuse(false);

        UserPasswordHistoryStore.record(dao, relaxed, PRINCIPAL, CURRENT);

        assertEquals(0, dao.entries.size());
    }

    @Test
    void aFailingHistoryWriteDoesNotUndoAPasswordAlreadyInEffect() {
        dao.failWrites = true;

        UserPasswordHistoryStore.record(dao, policy(), PRINCIPAL, CURRENT);

        // no exception escapes to the caller, which has already changed the password
        assertEquals(0, dao.entries.size());
    }

    /** An in-memory stand-in, ordered most recent first as the real query is. */
    private static class FakeDao implements UserPasswordHistoryDao {
        private final List<UserPasswordHistoryEntry> entries = new ArrayList<>();
        private boolean failWrites;
        private int reads;

        @Override
        public List<UserPasswordHistoryEntry> getByPrincipal(String principal, int limit) {
            reads++;
            List<UserPasswordHistoryEntry> matching = new ArrayList<>();
            for (UserPasswordHistoryEntry entry : entries) {
                if (entry.getPrincipal().equals(principal)) {
                    matching.add(entry);
                }
            }
            matching.sort(Comparator.comparing(UserPasswordHistoryEntry::getChangeDate).reversed());
            return matching.size() > limit ? matching.subList(0, limit) : matching;
        }

        @Override
        public void save(UserPasswordHistoryEntry entry) {
            if (failWrites) {
                throw new IllegalStateException("simulated write failure"); //$NON-NLS-1$
            }
            entries.add(entry);
        }

        @Override
        public void cleanup(String principal, Date threshold, int keep) {
            entries.removeIf(entry -> entry.getPrincipal().equals(principal)
                    && entry.getChangeDate().before(threshold));
        }
    }
}
