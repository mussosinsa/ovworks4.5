package org.ovirt.engine.core.common.utils;

public final class Ipv4AddressUtils {

    private Ipv4AddressUtils() {
    }

    public static boolean isValidAddress(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }

        String[] octets = value.split("\\.", -1); //$NON-NLS-1$
        if (octets.length != 4) {
            return false;
        }

        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3) {
                return false;
            }
            int number = 0;
            for (int index = 0; index < octet.length(); index++) {
                char character = octet.charAt(index);
                if (character < '0' || character > '9') {
                    return false;
                }
                number = number * 10 + character - '0';
            }
            if (number > 255) {
                return false;
            }
        }
        return true;
    }

    /** @return true when the value is one IPv4 address, or one IPv4 address with a CIDR prefix */
    public static boolean isValidAddressOrCidr(String value) {
        if (value == null) {
            return false;
        }
        int separator = value.indexOf('/');
        if (separator < 0) {
            return isValidAddress(value);
        }
        if (separator == 0 || separator != value.lastIndexOf('/') || separator == value.length() - 1
                || !isValidAddress(value.substring(0, separator))) {
            return false;
        }
        return parsePrefixLength(value.substring(separator + 1)) >= 0;
    }

    /**
     * Whether an address or range may stand for a terminal that is allowed to reach the engine.
     *
     * <p>Being well formed is not enough. Some values allow every address through, which is the
     * opposite of what a list of permitted terminals is for; others name addresses no terminal can
     * be reached at, so allowing them says nothing while looking like it says something. Both are
     * refused here rather than written into the web server's configuration, where they would read
     * as a restriction that is not one.</p>
     *
     * <p>Refused: a prefix of zero, which matches every address; {@code 0.0.0.0/8}, the unspecified
     * address and "this network"; {@code 224.0.0.0/4}, multicast; and {@code 240.0.0.0/4}, reserved
     * and holding the broadcast address {@code 255.255.255.255}. A range is refused when it reaches
     * into any of those, so a range that is broad enough to swallow one cannot be used to smuggle
     * it in.</p>
     *
     * <p>Loopback is deliberately left alone. Setup puts {@code 127.0.0.1} on the list itself, and
     * refusing it here would stop an administrator from keeping it there.</p>
     *
     * @return true when the value may be registered
     */
    public static boolean isUsableTerminalAddress(String value) {
        if (!isValidAddressOrCidr(value)) {
            return false;
        }

        int separator = value.indexOf('/');
        int prefixLength = separator < 0 ? ADDRESS_BITS : parsePrefixLength(value.substring(separator + 1));
        if (prefixLength == 0) {
            // matches every address, which would leave nothing restricted
            return false;
        }

        long address = toBits(separator < 0 ? value : value.substring(0, separator));
        long mask = prefixLength == 0 ? 0L : (ALL_BITS << (ADDRESS_BITS - prefixLength)) & ALL_BITS;
        long first = address & mask;
        long last = first | (~mask & ALL_BITS);

        for (long[] reserved : RESERVED_RANGES) {
            if (first <= reserved[1] && last >= reserved[0]) {
                return false;
            }
        }
        return true;
    }

    private static final int ADDRESS_BITS = 32;
    private static final long ALL_BITS = 0xFFFFFFFFL;

    /** first and last address of each block no terminal can be reached at, as unsigned 32 bit. */
    private static final long[][] RESERVED_RANGES = {
        { 0x00000000L, 0x00FFFFFFL }, // 0.0.0.0/8      unspecified, "this network"
        { 0xE0000000L, 0xEFFFFFFFL }, // 224.0.0.0/4    multicast
        { 0xF0000000L, 0xFFFFFFFFL }, // 240.0.0.0/4    reserved, holds 255.255.255.255
    };

    private static long toBits(String address) {
        String[] octets = address.split("\\.", -1); //$NON-NLS-1$
        long bits = 0;
        for (String octet : octets) {
            bits = (bits << 8) | Integer.parseInt(octet);
        }
        return bits;
    }

    /** @return the prefix length, or -1 when it is not a plain number from 0 to 32 */
    private static int parsePrefixLength(String prefix) {
        if (prefix.isEmpty() || prefix.length() > 2) {
            return -1;
        }
        int length = 0;
        for (int index = 0; index < prefix.length(); index++) {
            char character = prefix.charAt(index);
            if (character < '0' || character > '9') {
                return -1;
            }
            length = length * 10 + character - '0';
        }
        // a leading zero would make two spellings of the same prefix, and only one can be written back
        if (prefix.length() > 1 && prefix.charAt(0) == '0') {
            return -1;
        }
        return length <= ADDRESS_BITS ? length : -1;
    }
}
