// Modified by 새올정보기술 for OV-Works (2026). Changes against oVirt Engine 4.5.6: docs/ovworks-source-change-statement.md
package org.ovirt.engine.core.common;

public enum EventNotificationMethod {
    SMTP("smtp"),
    SNMP("snmp"),
    /**
     * Push through an ntfy server. Configured in the notifier only (NOTIFICATION_CHANNELS); never
     * stored as a subscription method, which stays smtp or snmp.
     */
    NTFY("ntfy");

    /**
     * External string representation (database, text configuration)
     */
    private String value;

    /**
     * Sets external string representation as lowercase name
     */
    private EventNotificationMethod(String value) {
        this.value = value;
    }

    /**
     * Return string representation (database, configuration
     */
    public String getAsString() {
        return value;
    }

    /**
     * Returns enum value based on external string representation
     */
    public static EventNotificationMethod valueOfString(String value) {
        return value != null ? valueOf(value.toUpperCase()) : null;
    }
}
