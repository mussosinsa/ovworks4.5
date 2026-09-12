package org.ovirt.engine.core.bll.aaa;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reading what {@code ovirt-aaa-jdbc-tool} printed.
 *
 * <p>The commands that create a local user and a local group both need the identifier the internal
 * authorization provider assigned to what they just made, and both get it the same way, so it is
 * read here rather than in one of them and borrowed by the other.</p>
 */
final class AaaJdbcTool {

    /** {@code ID: 6be45bbc-ad97-11f1-9f56-566f0a1b2c3d} on a line of its own. */
    private static final Pattern ID_FIELD =
            Pattern.compile("(?im)^\\s*id\\s*:\\s*([0-9a-f-]{36})\\s*$"); //$NON-NLS-1$

    /** {@code -- User user01(6be45bbc-ad97-11f1-9f56-566f0a1b2c3d) --} */
    private static final Pattern ID_IN_BRACKETS =
            Pattern.compile("(?i)\\(([0-9a-f-]{36})\\)"); //$NON-NLS-1$

    private AaaJdbcTool() {
    }

    /**
     * Reads the principal identifier out of what a {@code show} printed.
     *
     * <p>Two shapes are accepted because the tool has printed both: a field of its own, and the
     * identifier in brackets after the name in the heading. Whichever comes first is taken.</p>
     *
     * <p>This identifier is the one everything else matches a principal on, so a caller that cannot
     * get it must not make one up. {@code AddPermissionCommand} looks an existing user or group up
     * by it, and a row filed under anything else is not found - granting a permission then writes a
     * second row for the same principal, which nothing prevents: the tables are unique on
     * (domain, external_id), and two rows with different external ids are two different principals
     * as far as they are concerned.</p>
     *
     * @return the identifier, or null when neither shape is there - which is the tool having
     *         changed under us, and is reported rather than guessed at
     */
    static String principalIdOf(String output) {
        if (output == null) {
            return null;
        }
        Matcher field = ID_FIELD.matcher(output);
        if (field.find()) {
            return field.group(1);
        }
        Matcher heading = ID_IN_BRACKETS.matcher(output);
        return heading.find() ? heading.group(1) : null;
    }
}
