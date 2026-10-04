package org.ovirt.engine.core.notifier;

import java.util.Locale;

import org.apache.commons.lang.StringUtils;

/**
 * Which channels deliver the event notifications: e-mail, ntfy push, or both.
 *
 * <p>Read from {@code NOTIFICATION_CHANNELS}, a comma separated list of {@code mail} and
 * {@code ntfy} ({@code smtp}/{@code email} and {@code push} are accepted as the same, and
 * {@code both} as both). Unset means {@code mail}, which is how the notifier behaved before the
 * setting existed.</p>
 *
 * <p>The subscriptions decide <em>which</em> events are sent - the e-mail subscriptions made in the
 * administration portal and the {@code FILTER} entries - and this decides <em>how</em>. With ntfy
 * selected, each event that matched an e-mail subscription is also pushed, once, to
 * {@code NTFY_TOPIC}; with mail not selected, no e-mail is sent.</p>
 */
public final class NotificationChannels {

    public static final String NOTIFICATION_CHANNELS = "NOTIFICATION_CHANNELS";

    private final boolean mail;
    private final boolean ntfy;

    private NotificationChannels(boolean mail, boolean ntfy) {
        this.mail = mail;
        this.ntfy = ntfy;
    }

    /**
     * @param configured the value of NOTIFICATION_CHANNELS, or null
     * @throws IllegalArgumentException for a channel this does not know, so that a misspelt value
     *             stops the notifier at start instead of silently sending nothing
     */
    public static NotificationChannels parse(String configured) {
        if (StringUtils.isBlank(configured)) {
            return new NotificationChannels(true, false);
        }
        boolean mail = false;
        boolean ntfy = false;
        for (String item : configured.split("[,\\s]+")) {
            String channel = item.trim().toLowerCase(Locale.ROOT);
            switch (channel) {
            case "":
                break;
            case "mail":
            case "email":
            case "smtp":
                mail = true;
                break;
            case "ntfy":
            case "push":
                ntfy = true;
                break;
            case "both":
                mail = true;
                ntfy = true;
                break;
            default:
                throw new IllegalArgumentException(
                        NOTIFICATION_CHANNELS + " must list mail and/or ntfy (e.g. \"mail\", \"ntfy\", "
                                + "\"mail,ntfy\"): unknown channel '" + item.trim() + "'");
            }
        }
        if (!mail && !ntfy) {
            throw new IllegalArgumentException(NOTIFICATION_CHANNELS + " selects no channel: " + configured);
        }
        return new NotificationChannels(mail, ntfy);
    }

    public boolean isMail() {
        return mail;
    }

    public boolean isNtfy() {
        return ntfy;
    }

    @Override
    public String toString() {
        return mail && ntfy ? "mail,ntfy" : mail ? "mail" : "ntfy";
    }
}
