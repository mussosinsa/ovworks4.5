package org.ovirt.engine.core.bll;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the lines the web server writes when it turns an address away.
 *
 * <p>An address that is not registered never reaches the engine: the web server refuses it at the
 * {@code Require ip} block and the request goes no further. What it writes about the refusal is
 * therefore the only account of the attempt there is, and this reads it.</p>
 *
 * <p>The format is the {@code ovirt_admin_access_denied_audit} LogFormat in
 * ovirt-engine-proxy.conf. A change there needs the same change here.</p>
 */
public final class ClientAccessDeniedLog {

    /** {@code remote_ip=192.168.40.50}, and the rest of the fields written beside it. */
    private static final Pattern FIELD =
            Pattern.compile("(\\w+)=(\"[^\"]*\"|\\S+)");

    private ClientAccessDeniedLog() {
    }

    /** One refusal, as the web server recorded it. */
    public static final class Denial {
        private final String time;
        private final String address;
        private final String request;

        Denial(String time, String address, String request) {
            this.time = time;
            this.address = address;
            this.request = request;
        }

        /** When the web server refused the request, in its own local time. */
        public String getTime() {
            return time;
        }

        /** The address that was turned away. */
        public String getAddress() {
            return address;
        }

        /** The request line it was turned away from, or an empty string. */
        public String getRequest() {
            return request;
        }

        /** What goes in the event list, saying who was turned away and from what. */
        public String describe() {
            StringBuilder message = new StringBuilder("Access to the engine was denied to ") //$NON-NLS-1$
                    .append(address)
                    .append(" because the address is not registered"); //$NON-NLS-1$
            if (!time.isEmpty()) {
                message.append(" at ").append(time); //$NON-NLS-1$
            }
            if (!request.isEmpty()) {
                message.append("; request: ").append(request); //$NON-NLS-1$
            }
            return message.toString();
        }
    }

    /**
     * @param line one line of the log
     * @return the refusal it records, or empty when the line carries no address - a line the web
     *         server wrote in another format, or half a line caught mid-write
     */
    public static Optional<Denial> parse(String line) {
        if (line == null || line.isBlank()) {
            return Optional.empty();
        }
        String time = "";
        String address = "";
        String request = "";
        Matcher matcher = FIELD.matcher(line);
        while (matcher.find()) {
            String value = unquote(matcher.group(2));
            switch (matcher.group(1)) {
                case "time":
                    time = value;
                    break;
                case "remote_ip":
                    address = value;
                    break;
                case "request":
                    request = value;
                    break;
                default:
                    break;
            }
        }
        if (address.isEmpty() || "-".equals(address)) {
            return Optional.empty();
        }
        return Optional.of(new Denial(time, address, "-".equals(request) ? "" : request));
    }

    private static String unquote(String value) {
        return value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")
                ? value.substring(1, value.length() - 1)
                : value;
    }
}
