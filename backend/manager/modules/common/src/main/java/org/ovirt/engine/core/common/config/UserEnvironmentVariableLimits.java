package org.ovirt.engine.core.common.config;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * The range a user environment variable may be set to.
 *
 * <p>These variables are held by ovirt-aaa-jdbc-tool rather than by the engine configuration, so
 * they carry none of the validValues that engine-config options have. The ones that decide a
 * security control need a range all the same, and it has to be the same range wherever it is
 * applied - the screen that offers the value and the command that writes it both read it from
 * here.</p>
 */
public class UserEnvironmentVariableLimits {

    /**
     * How many consecutive failed logins lock an account.
     *
     * <p>Bounded at five to match {@code ENGINE_SSO_ADMIN_LOCK_MAX_FAILURES}, the engine side
     * setting for the same control, which engine-config declares as {@code 1..5}. Zero is not
     * offered: in ovirt-aaa-jdbc-tool it turns the lockout off altogether, which is the opposite
     * of what bounding this value is for.</p>
     */
    public static final String MAX_FAILURES_SINCE_SUCCESS = "MAX_FAILURES_SINCE_SUCCESS"; //$NON-NLS-1$

    /**
     * How long a locked account stays locked, in minutes.
     *
     * <p>This is the provider's half of a lock the engine also keeps, and the two have to agree:
     * they are counted separately and released separately, so a provider that holds its lock for
     * longer than {@code ENGINE_SSO_USER_LOCK_MINUTES} leaves the account unable to log in after
     * the engine has announced the account unlocked. ovirt-aaa-jdbc-tool ships this at 60 while
     * the engine setting starts at 5.</p>
     *
     * <p>Bounded to the same 5..100000 that engine-config declares for the engine setting, so
     * that whichever of the two is being set can be set to the same number.</p>
     */
    public static final String LOCK_MINUTES = "LOCK_MINUTES"; //$NON-NLS-1$

    private static final Map<String, int[]> LIMITS;

    static {
        Map<String, int[]> limits = new HashMap<>();
        limits.put(MAX_FAILURES_SINCE_SUCCESS, new int[] { 1, 5 });
        limits.put(LOCK_MINUTES, new int[] { 5, 100000 });
        LIMITS = Collections.unmodifiableMap(limits);
    }

    private UserEnvironmentVariableLimits() {
    }

    /** @return true when the variable is one this class bounds */
    public static boolean isBounded(String key) {
        return key != null && LIMITS.containsKey(key.trim());
    }

    /**
     * @return true when the value is acceptable for the variable: a whole number, and within the
     *         range when the variable has one. A variable without a range accepts any whole number.
     */
    public static boolean isWithinLimits(String key, String value) {
        if (value == null || !value.trim().matches("[0-9]+")) { //$NON-NLS-1$
            return false;
        }
        int[] range = key == null ? null : LIMITS.get(key.trim());
        if (range == null) {
            return true;
        }
        int number;
        try {
            number = Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            // longer than an int, so past any range this class defines
            return false;
        }
        return number >= range[0] && number <= range[1];
    }

    /** @return the smallest accepted value, or -1 when the variable has no range */
    public static int minimum(String key) {
        int[] range = key == null ? null : LIMITS.get(key.trim());
        return range == null ? -1 : range[0];
    }

    /** @return the largest accepted value, or -1 when the variable has no range */
    public static int maximum(String key) {
        int[] range = key == null ? null : LIMITS.get(key.trim());
        return range == null ? -1 : range[1];
    }
}
