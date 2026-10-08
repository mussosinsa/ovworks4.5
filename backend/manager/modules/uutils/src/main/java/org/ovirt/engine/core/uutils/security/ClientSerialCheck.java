package org.ovirt.engine.core.uutils.security;

import java.io.File;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Decides whether a request came from a registered terminal, and how often a refusal is recorded.
 *
 * <p>A terminal proves itself with the {@value #HEADER} header, which has to carry the serial in
 * {@value #CONFIG_FILE}. The welcome page, the SSO and the REST API each check it, and each used to
 * have its own copy of the comparison and nothing at all for recording the ones it turned away. A
 * request without the header is the access this check exists to stop, so a refusal is something
 * the audit log is for - and also something anyone can produce at will, which is why
 * {@link #shouldReport} decides how many of them reach it.</p>
 */
public final class ClientSerialCheck {

    /** The header a terminal presents. */
    public static final String HEADER = "X-Client-Serial"; //$NON-NLS-1$

    /** Where the expected serial is kept. */
    public static final String CONFIG_FILE = "/etc/ovirt-engine/encryptor/config.json"; //$NON-NLS-1$

    /** The engine event a refusal is recorded as; the engine accepts it by this name. */
    public static final String AUDIT_LOG_TYPE = "CLIENT_SERIAL_REJECTED"; //$NON-NLS-1$

    /**
     * How long one source, refused at one place for one reason, is recorded only once.
     *
     * <p>The refusal happens before anyone has logged in. Without a bound, a loop sending requests
     * without the header would write a row per request into the event table - filling the very
     * log it is meant to appear in, and pushing out what is in it.</p>
     */
    public static final long REPORT_INTERVAL_MILLIS = 60_000L;

    /** Beyond this many remembered sources the memory is cleared rather than grown. */
    static final int MAX_REMEMBERED = 10_000;

    /** Why a request was refused. Only these words reach the logs - never the serial itself. */
    public enum Refusal {
        /** The request carried no header at all. */
        MISSING("no X-Client-Serial header"), //$NON-NLS-1$
        /** It carried one, and it is not the registered serial. */
        INVALID("an X-Client-Serial header that does not match"), //$NON-NLS-1$
        /** The registered serial could not be read, so nothing could be let in. */
        UNVERIFIABLE("an X-Client-Serial header that could not be checked: the registered serial is unavailable"); //$NON-NLS-1$

        private final String description;

        Refusal(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    private static final ClientSerialCheck SHARED = new ClientSerialCheck(System::currentTimeMillis);

    private final LongSupplier clock;
    private final Map<String, Long> lastReported = new ConcurrentHashMap<>();

    ClientSerialCheck(LongSupplier clock) {
        this.clock = clock;
    }

    /**
     * @param presented the header the request carried, or null
     * @param expected the registered serial, or null when it could not be read
     * @return why the request is refused, or null when it may go on
     */
    public static Refusal check(String presented, String expected) {
        if (StringUtils.isEmpty(presented)) {
            return Refusal.MISSING;
        }
        if (StringUtils.isEmpty(expected)) {
            return Refusal.UNVERIFIABLE;
        }
        // Compared in constant time: how long a wrong guess takes to refuse says nothing about
        // how much of it was right.
        return MessageDigest.isEqual(
                presented.getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8)) ? null : Refusal.INVALID;
    }

    /** An IPv4 literal, so that nothing that is a host name is ever looked up. */
    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$"); //$NON-NLS-1$

    /** An IPv6 literal, with or without an interface zone. */
    private static final Pattern IPV6 = Pattern.compile("^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(%[0-9A-Za-z_.-]+)?$"); //$NON-NLS-1$

    /**
     * Whether a request comes from the engine host itself: the loopback interface, or an address
     * one of this host's own interfaces carries.
     *
     * <p>Such a request is not from a terminal. It is a program on the engine host - the engine
     * itself (the JBoss management login plugin), the external network provider, a tool talking to
     * the API - none of which carries a terminal's serial, and each of which was refused and
     * recorded as an unregistered terminal while the engine's own address was on the list of
     * terminals allowed in. Only literal addresses are judged, never a name: a name would be
     * looked up, and a lookup is not something a request should be able to make the engine do.</p>
     *
     * @param address the address of the request's source, as the connection or the engine says it
     */
    public static boolean isThisHost(String address) {
        if (StringUtils.isEmpty(address)) {
            return false;
        }
        String literal = address.trim();
        boolean v6 = IPV6.matcher(literal).matches();
        if (!v6 && !IPV4.matcher(literal).matches()) {
            return false;
        }
        if (v6 && literal.indexOf('%') >= 0) {
            literal = literal.substring(0, literal.indexOf('%'));
        }
        try {
            InetAddress inet = InetAddress.getByName(literal);
            return inet.isLoopbackAddress() || NetworkInterface.getByInetAddress(inet) != null;
        } catch (Exception exception) {
            return false;
        }
    }

    /** Checks the header against the registered serial, read afresh so a change needs no restart. */
    public static Refusal check(String presented) {
        return check(presented, loadExpected());
    }

    /** @return the registered serial, or null when there is none to be read */
    public static String loadExpected() {
        try {
            String serial = new ObjectMapper().readTree(new File(CONFIG_FILE)).path("serialNum").asText(); //$NON-NLS-1$
            return StringUtils.isEmpty(serial) ? null : serial;
        } catch (Exception exception) {
            return null;
        }
    }

    /** What the event says about a refusal: where, and why. Never what was presented. */
    public static String describe(String path, Refusal refusal) {
        return String.format("%s presented %s", //$NON-NLS-1$
                StringUtils.defaultIfEmpty(path, "/"), //$NON-NLS-1$
                refusal.getDescription());
    }

    /** Whether this refusal is the first from its source, at its place, for its reason, in a while. */
    public static boolean shouldReport(String sourceAddress, String path, Refusal refusal) {
        return SHARED.isDue(sourceAddress, path, refusal);
    }

    boolean isDue(String sourceAddress, String path, Refusal refusal) {
        long now = clock.getAsLong();
        if (lastReported.size() >= MAX_REMEMBERED) {
            lastReported.clear();
        }
        String key = sourceAddress + '|' + path + '|' + refusal;
        boolean[] due = new boolean[1];
        lastReported.compute(key, (k, last) -> {
            if (last == null || now - last >= REPORT_INTERVAL_MILLIS) {
                due[0] = true;
                return now;
            }
            return last;
        });
        return due[0];
    }
}
