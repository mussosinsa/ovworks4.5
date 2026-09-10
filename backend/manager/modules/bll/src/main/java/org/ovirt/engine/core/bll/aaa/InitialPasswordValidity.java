package org.ovirt.engine.core.bll.aaa;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Works out the {@code --password-valid-to} that ovirt-aaa-jdbc-tool is given when an
 * administrator assigns a password.
 *
 * <p>Assigning a password is either creating a local user or resetting an existing one, and both
 * answer to {@code PasswordPolicyForceChangeOnFirstLogin}. They share this so that the two paths
 * cannot drift apart: the setting either sends both of them into the credential-change flow on the
 * next login, or neither.
 */
public class InitialPasswordValidity {

    /** How long an assigned password lasts when the user is not made to change it. */
    private static final int VALIDITY_YEARS = 1;

    /**
     * How far in the past an expired password is dated. Dating it at the current instant would
     * leave whether it counts as expired to the comparison ovirt-aaa-jdbc-tool happens to make.
     */
    private static final int EXPIRY_MARGIN_MINUTES = 1;

    /** The format ovirt-aaa-jdbc-tool parses. The offset is included, so it reads unambiguously. */
    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssX"); //$NON-NLS-1$

    private InitialPasswordValidity() {
    }

    /**
     * @param forceChangeOnFirstLogin whether the user has to replace the assigned password before
     *        being let in. When set, the password is stored already expired, which makes the
     *        authentication provider report expired credentials on the next login and sends the
     *        user to the password change flow before anything else is served.
     */
    public static String validTo(boolean forceChangeOnFirstLogin) {
        return format(forceChangeOnFirstLogin
                ? ZonedDateTime.now().minusMinutes(EXPIRY_MARGIN_MINUTES)
                : ZonedDateTime.now().plusYears(VALIDITY_YEARS));
    }

    /** Reads back a value produced by {@link #validTo(boolean)}. */
    public static ZonedDateTime parse(String validTo) {
        return ZonedDateTime.parse(validTo, FORMAT);
    }

    private static String format(ZonedDateTime validTo) {
        return validTo.format(FORMAT);
    }
}
