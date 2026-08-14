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
}
