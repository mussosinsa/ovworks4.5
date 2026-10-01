package org.ovirt.engine.core.common.action;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The rules for the command blacklist of the VM security dialog, shared by the dialog and the
 * engine so that what the dialog accepts is what the engine applies.
 *
 * <p>A blacklist entry is refused inside the guest by a Software Restriction path rule, which names
 * a file and nothing else. So an entry is a program, not a command line: {@code netstat -a} blocks
 * {@code netstat.exe} with every argument, and {@code rm -rf} blocks a program called {@code rm}.
 * The arguments are dropped when the entry is added, so that the list shows what is really
 * refused.</p>
 *
 * <p>Compiled for the browser as well, so it keeps to what GWT emulates: no {@code Pattern}, no
 * {@code String.format}.</p>
 */
public final class CommandBlacklist {

    /** Separates a program from its description in one line of the list. */
    public static final String FIELD_SEPARATOR = "\t"; //$NON-NLS-1$

    /** Separates the lines of the list. */
    public static final String LINE_SEPARATOR = "\n"; //$NON-NLS-1$

    /** More than enough for a blacklist, and a bound on the script that applies it. */
    public static final int MAX_ENTRIES = 200;

    public static final int MAX_DESCRIPTION_LENGTH = 100;

    /** Why an entry could not be added. */
    public enum Problem {
        /** Not something that names a program. */
        INVALID,
        /** A program Windows needs to sign in or keep a session, which would lock everyone out. */
        PROTECTED,
        /** A description that is too long, or holds a tab or a line break. */
        INVALID_DESCRIPTION
    }

    /** The extensions a rule is applied to; anything else is not a program Windows would run. */
    private static final String PROGRAM_PATTERN =
            "[a-z0-9_][a-z0-9._-]{0,63}\\.(exe|com|bat|cmd|msc|cpl|ps1|vbs|vbe|js|jse|wsf|hta|msi|scr)"; //$NON-NLS-1$

    /** The commands Windows still ships as .com, so that "format" blocks the format there is. */
    private static final List<String> COM_PROGRAMS = Arrays.asList(
            "chcp", "diskcomp", "diskcopy", "format", "mode", "more", "tree"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$ //$NON-NLS-6$ //$NON-NLS-7$

    /**
     * What may not be blacklisted: the programs that sign a user in and hold their session, and
     * the guest agent this dialog works through. A rule on one of these applies to every account,
     * the administrators included, and leaves nobody able to reach a desktop to undo it.
     */
    private static final List<String> PROTECTED_PROGRAMS = Arrays.asList(
            "explorer.exe", "winlogon.exe", "userinit.exe", "logonui.exe", "csrss.exe", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
            "lsass.exe", "services.exe", "svchost.exe", "smss.exe", "wininit.exe", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
            "dwm.exe", "sihost.exe", "ctfmon.exe", "fontdrvhost.exe", "qemu-ga.exe"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$

    private CommandBlacklist() {
    }

    /**
     * The program an entry refers to, as the rule names it.
     *
     * <p>The first word only, without a folder in front of it - a rule naming the file alone
     * refuses it wherever it is - in lower case, and with {@code .exe} (or {@code .com} for the few
     * commands that are) when no extension was given.</p>
     *
     * @return the program, or null when the entry does not name one
     */
    public static String normalize(String entry) {
        if (entry == null) {
            return null;
        }
        String program = entry.trim();
        if (program.startsWith("\"")) { //$NON-NLS-1$
            int end = program.indexOf('"', 1);
            program = end < 0 ? program.substring(1) : program.substring(1, end);
        } else {
            int space = firstWhitespace(program);
            if (space >= 0) {
                program = program.substring(0, space);
            }
        }
        int folder = Math.max(program.lastIndexOf('\\'), program.lastIndexOf('/'));
        program = program.substring(folder + 1).toLowerCase();
        if (program.isEmpty()) {
            return null;
        }
        if (program.indexOf('.') < 0) {
            program = program + (COM_PROGRAMS.contains(program) ? ".com" : ".exe"); //$NON-NLS-1$ //$NON-NLS-2$
        }
        return program.matches(PROGRAM_PATTERN) ? program : null;
    }

    private static int firstWhitespace(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) <= ' ') {
                return i;
            }
        }
        return -1;
    }

    /** @return why the entry cannot be added, or null when it can */
    public static Problem check(String entry, String description) {
        String program = normalize(entry);
        if (program == null) {
            return Problem.INVALID;
        }
        if (PROTECTED_PROGRAMS.contains(program)) {
            return Problem.PROTECTED;
        }
        if (!isValidDescription(description)) {
            return Problem.INVALID_DESCRIPTION;
        }
        return null;
    }

    public static boolean isValidDescription(String description) {
        if (description == null) {
            return true;
        }
        if (description.length() > MAX_DESCRIPTION_LENGTH) {
            return false;
        }
        for (int i = 0; i < description.length(); i++) {
            char c = description.charAt(i);
            if (c < ' ' || c == 0x7f) {
                return false;
            }
        }
        return true;
    }

    /** One line per entry: the program, the separator, the description. */
    public static String encode(List<String[]> entries) {
        StringBuilder list = new StringBuilder();
        for (String[] entry : entries) {
            if (list.length() > 0) {
                list.append(LINE_SEPARATOR);
            }
            list.append(entry[0]).append(FIELD_SEPARATOR).append(entry.length > 1 && entry[1] != null ? entry[1] : ""); //$NON-NLS-1$
        }
        return list.toString();
    }

    /**
     * Reads a list written by {@link #encode} or by the guest.
     *
     * @return the entries as program and description, in the order given; blank lines skipped
     */
    public static List<String[]> decode(String list) {
        List<String[]> entries = new ArrayList<>();
        if (list == null) {
            return entries;
        }
        for (String line : list.split(LINE_SEPARATOR)) {
            String entry = line.replace("\r", ""); //$NON-NLS-1$ //$NON-NLS-2$
            if (entry.trim().isEmpty()) {
                continue;
            }
            int separator = entry.indexOf(FIELD_SEPARATOR);
            entries.add(separator < 0
                    ? new String[] { entry.trim(), "" } //$NON-NLS-1$
                    : new String[] { entry.substring(0, separator).trim(), entry.substring(separator + 1).trim() });
        }
        return entries;
    }

    /**
     * Whether a whole list can be applied as it stands: every program already in the form
     * {@link #normalize} gives, none protected, none twice, and no more of them than allowed.
     */
    public static boolean isApplicable(List<String[]> entries) {
        if (entries.size() > MAX_ENTRIES) {
            return false;
        }
        List<String> seen = new ArrayList<>();
        for (String[] entry : entries) {
            String program = entry[0];
            if (program == null || !program.equals(normalize(program)) || seen.contains(program)
                    || check(program, entry.length > 1 ? entry[1] : null) != null) {
                return false;
            }
            seen.add(program);
        }
        return true;
    }
}
