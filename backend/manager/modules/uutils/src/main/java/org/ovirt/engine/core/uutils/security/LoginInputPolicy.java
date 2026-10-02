package org.ovirt.engine.core.uutils.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * What the login ID and the password may hold, wherever they are typed in.
 *
 * <p>Both are at most {@link #MAX_LENGTH} characters, and neither may hold a pipe, a semicolon, a
 * colon, a backtick or any kind of blank: characters a command line, a field separator or a SQL
 * statement give a meaning to, and none of which a login needs. The login ID, which is only ever
 * letters, digits and {@code . _ - @}, is also refused the quotes and the operators a query is
 * broken out of with. And neither may carry what a SQL injection is made of: a quote followed by
 * {@code OR}, a tautology like {@code 1=1}, a comment, a {@code UNION SELECT}.</p>
 *
 * <p>No login is checked against a SQL statement built from what was typed - the credentials go to
 * the authentication extension as values, never as text of a query - so this is a second line, the
 * one an inspection checks for: a malformed login is turned away at the door, before any extension,
 * any lockout counter or any log line that would hold it.</p>
 *
 * <p>The login page enforces the same rules as the user types, from the patterns {@link #toJson()}
 * hands it, so the two cannot drift apart. The server checks again, since a page can be bypassed.</p>
 */
public final class LoginInputPolicy {

    /** The most characters a login ID or a password may have. */
    public static final int MAX_LENGTH = 20;

    /** Refused in both fields, besides blanks and control characters. */
    public static final String FORBIDDEN_CHARACTERS = "|;:`"; //$NON-NLS-1$

    /** Refused in the login ID only: quotes and the operators an injected condition is written with. */
    public static final String USER_NAME_FORBIDDEN_CHARACTERS = "'\"=<>(),*"; //$NON-NLS-1$

    /**
     * The shapes of a SQL injection, as regular expressions both Java and a browser read the same
     * way (no look-behind), matched without regard to case.
     */
    static final List<String> SQL_INJECTION_PATTERNS = Collections.unmodifiableList(Arrays.asList(
            // ' or ...   ") and ...
            "['\")]\\s*(or|and|xor)(?![a-zA-Z])", //$NON-NLS-1$
            // or 1=1   or'a'='a   and x>y
            "(^|[^a-zA-Z])(or|and)\\s*['\"(]?\\s*\\w+\\s*['\"]?\\s*(=|<|>)", //$NON-NLS-1$
            // '='   '<>'
            "['\"]\\s*(=|<>|!=)\\s*['\"]", //$NON-NLS-1$
            // comments
            "--|/\\*|\\*/", //$NON-NLS-1$
            // statements
            "\\bunion\\b.*\\bselect\\b", //$NON-NLS-1$
            "\\bselect\\b.*\\bfrom\\b", //$NON-NLS-1$
            "\\binsert\\b.*\\binto\\b", //$NON-NLS-1$
            "\\bdelete\\b.*\\bfrom\\b", //$NON-NLS-1$
            "\\bupdate\\b.*\\bset\\b", //$NON-NLS-1$
            "\\b(drop|truncate|alter)\\b.*\\b(table|database|schema|user)\\b", //$NON-NLS-1$
            // functions an injection probes with
            "\\b(sleep|pg_sleep|benchmark|exec|execute)\\s*\\(", //$NON-NLS-1$
            "\\bwaitfor\\b.*\\bdelay\\b", //$NON-NLS-1$
            "xp_cmdshell|information_schema|pg_catalog")); //$NON-NLS-1$

    private static final List<Pattern> SQL_INJECTION = SQL_INJECTION_PATTERNS.stream()
            .map(pattern -> Pattern.compile(pattern, Pattern.CASE_INSENSITIVE))
            .collect(Collectors.toList());

    /** Which field. */
    public enum Field {
        USER_NAME("아이디"), //$NON-NLS-1$
        PASSWORD("패스워드"); //$NON-NLS-1$

        private final String label;

        Field(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    /** Why a value was refused. The first that applies is the one reported. */
    public enum Problem {
        TOO_LONG,
        FORBIDDEN_CHARACTER,
        SQL_INJECTION
    }

    /** A refused value: the field and why. It never holds the value itself. */
    public static final class Refusal {
        private final Field field;
        private final Problem problem;

        Refusal(Field field, Problem problem) {
            this.field = field;
            this.problem = problem;
        }

        public Field getField() {
            return field;
        }

        public Problem getProblem() {
            return problem;
        }

        /** What the user is told, in Korean like the rest of the login page. */
        public String getMessage() {
            return message(field, problem);
        }

        @Override
        public String toString() {
            return field + ":" + problem; //$NON-NLS-1$
        }
    }

    private LoginInputPolicy() {
    }

    /** Checks a login ID. Empty or null is not refused here: a missing ID is a failed login. */
    public static Optional<Refusal> checkUserName(String userName) {
        return check(Field.USER_NAME, userName);
    }

    /** Checks a password. Empty or null is not refused here: a missing password is a failed login. */
    public static Optional<Refusal> checkPassword(String password) {
        return check(Field.PASSWORD, password);
    }

    /** Checks both, the ID first. */
    public static Optional<Refusal> check(String userName, String password) {
        Optional<Refusal> refusal = checkUserName(userName);
        return refusal.isPresent() ? refusal : checkPassword(password);
    }

    static Optional<Refusal> check(Field field, String value) {
        if (value == null || value.isEmpty()) {
            return Optional.empty();
        }
        if (value.length() > MAX_LENGTH) {
            return Optional.of(new Refusal(field, Problem.TOO_LONG));
        }
        for (int i = 0; i < value.length(); i++) {
            if (isForbidden(field, value.charAt(i))) {
                return Optional.of(new Refusal(field, Problem.FORBIDDEN_CHARACTER));
            }
        }
        for (Pattern pattern : SQL_INJECTION) {
            if (pattern.matcher(value).find()) {
                return Optional.of(new Refusal(field, Problem.SQL_INJECTION));
            }
        }
        return Optional.empty();
    }

    /** Whether the character may not be typed into the field. */
    public static boolean isForbidden(Field field, char c) {
        return FORBIDDEN_CHARACTERS.indexOf(c) >= 0
                || Character.isWhitespace(c)
                || Character.isSpaceChar(c)
                || Character.isISOControl(c)
                || field == Field.USER_NAME && USER_NAME_FORBIDDEN_CHARACTERS.indexOf(c) >= 0;
    }

    /** What the user is told about a refused field. */
    public static String message(Field field, Problem problem) {
        switch (problem) {
        case TOO_LONG:
            return String.format("%s는 최대 %d자까지 입력할 수 있습니다.", field.getLabel(), MAX_LENGTH); //$NON-NLS-1$
        case FORBIDDEN_CHARACTER:
            return String.format("%s에 사용 불가능한 특수문자가 포함되어 있습니다. (%s)", //$NON-NLS-1$
                    field.getLabel(),
                    describeForbidden(field));
        default:
            return String.format("%s에 허용되지 않는 입력(SQL 구문)이 포함되어 있습니다.", field.getLabel()); //$NON-NLS-1$
        }
    }

    static String describeForbidden(Field field) {
        String characters = field == Field.USER_NAME
                ? FORBIDDEN_CHARACTERS + USER_NAME_FORBIDDEN_CHARACTERS
                : FORBIDDEN_CHARACTERS;
        return characters.chars()
                .mapToObj(c -> String.valueOf((char) c))
                .collect(Collectors.joining(" ")) + " 공백"; //$NON-NLS-1$ //$NON-NLS-2$
    }

    /**
     * The rules, for the login page's script: the length, the characters of each field, the
     * patterns, and the messages. Safe to put inside a {@code <script>} element: {@code <}, {@code >}
     * and {@code &} are written as escapes, so nothing in it can close the element.
     */
    public static String toJson() {
        StringBuilder json = new StringBuilder();
        json.append("{\"maxLength\":").append(MAX_LENGTH); //$NON-NLS-1$
        json.append(",\"forbidden\":").append(quote(FORBIDDEN_CHARACTERS)); //$NON-NLS-1$
        json.append(",\"userNameForbidden\":").append(quote(USER_NAME_FORBIDDEN_CHARACTERS)); //$NON-NLS-1$
        json.append(",\"sqlInjection\":["); //$NON-NLS-1$
        json.append(SQL_INJECTION_PATTERNS.stream().map(LoginInputPolicy::quote).collect(Collectors.joining(","))); //$NON-NLS-1$
        json.append("],\"messages\":{"); //$NON-NLS-1$
        json.append(Arrays.stream(Field.values())
                .map(field -> quote(field.name()) + ":{" //$NON-NLS-1$
                        + Arrays.stream(Problem.values())
                                .map(problem -> quote(problem.name()) + ":" + quote(message(field, problem))) //$NON-NLS-1$
                                .collect(Collectors.joining(",")) //$NON-NLS-1$
                        + "}") //$NON-NLS-1$
                .collect(Collectors.joining(","))); //$NON-NLS-1$
        json.append("}}"); //$NON-NLS-1$
        return json.toString();
    }

    static String quote(String value) {
        StringBuilder quoted = new StringBuilder("\""); //$NON-NLS-1$
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                quoted.append('\\').append(c);
            } else if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == ' ' || c == ' ') {
                quoted.append(String.format("\\u%04x", (int) c)); //$NON-NLS-1$
            } else {
                quoted.append(c);
            }
        }
        return quoted.append('"').toString();
    }
}
