package org.ovirt.engine.core.notifier;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class NotificationChannelsTest {

    @Test
    public void unsetMeansMailAsBefore() {
        NotificationChannels channels = NotificationChannels.parse(null);
        assertTrue(channels.isMail());
        assertFalse(channels.isNtfy());
    }

    @Test
    public void selectsMailNtfyOrBoth() {
        assertFalse(NotificationChannels.parse("ntfy").isMail());
        assertTrue(NotificationChannels.parse("ntfy").isNtfy());
        assertTrue(NotificationChannels.parse("mail, ntfy").isMail());
        assertTrue(NotificationChannels.parse("mail, ntfy").isNtfy());
        assertTrue(NotificationChannels.parse("both").isNtfy());
        assertTrue(NotificationChannels.parse("SMTP").isMail());
    }

    @Test
    public void aMisspeltChannelStopsTheNotifier() {
        assertThrows(IllegalArgumentException.class, () -> NotificationChannels.parse("mail,ntyf"));
        assertThrows(IllegalArgumentException.class, () -> NotificationChannels.parse(","));
    }
}
