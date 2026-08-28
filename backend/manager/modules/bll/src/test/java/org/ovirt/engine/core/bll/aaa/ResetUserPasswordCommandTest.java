package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import org.junit.jupiter.api.Test;

class ResetUserPasswordCommandTest {
    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssX"); //$NON-NLS-1$

    @Test
    void passwordIsValidForOneYearByDefault() {
        ZonedDateTime before = ZonedDateTime.now().plusYears(1).minusSeconds(1);

        ZonedDateTime validTo = ZonedDateTime.parse(
                ResetUserPasswordCommand.passwordValidTo(false), FORMATTER);

        ZonedDateTime after = ZonedDateTime.now().plusYears(1).plusSeconds(1);
        assertTrue(!validTo.isBefore(before) && !validTo.isAfter(after));
    }

    @Test
    void forcedPasswordChangeStillCreatesAnExpiredPassword() {
        ZonedDateTime before = ZonedDateTime.now().minusMinutes(1).minusSeconds(1);

        ZonedDateTime validTo = ZonedDateTime.parse(
                ResetUserPasswordCommand.passwordValidTo(true), FORMATTER);

        ZonedDateTime after = ZonedDateTime.now().minusMinutes(1).plusSeconds(1);
        assertTrue(!validTo.isBefore(before) && !validTo.isAfter(after));
    }
}
