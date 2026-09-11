package org.ovirt.engine.core.common.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class UserEnvironmentVariableLimitsTest {

    private static final String BOUNDED = UserEnvironmentVariableLimits.MAX_FAILURES_SINCE_SUCCESS;
    private static final String UNBOUNDED = "SOME_OTHER_SETTING";

    @Test
    void shouldAcceptTheWholeAllowedRange() {
        for (int value = 1; value <= 5; value++) {
            assertTrue(UserEnvironmentVariableLimits.isWithinLimits(BOUNDED, String.valueOf(value)),
                    "값 " + value + " 는 허용되어야 한다");
        }
    }

    @Test
    void shouldRejectAnythingAboveFive() {
        assertFalse(UserEnvironmentVariableLimits.isWithinLimits(BOUNDED, "6"));
        assertFalse(UserEnvironmentVariableLimits.isWithinLimits(BOUNDED, "10"));
        assertFalse(UserEnvironmentVariableLimits.isWithinLimits(BOUNDED, "99999"));
    }

    @Test
    void shouldRejectZeroBecauseItTurnsTheLockoutOff() {
        assertFalse(UserEnvironmentVariableLimits.isWithinLimits(BOUNDED, "0"));
    }

    @Test
    void shouldRejectAValueThatIsNotAWholeNumber() {
        assertFalse(UserEnvironmentVariableLimits.isWithinLimits(BOUNDED, "-1"));
        assertFalse(UserEnvironmentVariableLimits.isWithinLimits(BOUNDED, "3.5"));
        assertFalse(UserEnvironmentVariableLimits.isWithinLimits(BOUNDED, "five"));
        assertFalse(UserEnvironmentVariableLimits.isWithinLimits(BOUNDED, ""));
        assertFalse(UserEnvironmentVariableLimits.isWithinLimits(BOUNDED, null));
    }

    @Test
    void shouldRejectANumberTooLargeForAnInt() {
        assertFalse(UserEnvironmentVariableLimits.isWithinLimits(BOUNDED, "99999999999999999999"));
    }

    @Test
    void shouldIgnoreSurroundingSpace() {
        assertTrue(UserEnvironmentVariableLimits.isWithinLimits(" " + BOUNDED + " ", " 5 "));
        assertFalse(UserEnvironmentVariableLimits.isWithinLimits(" " + BOUNDED + " ", " 6 "));
    }

    @Test
    void shouldLeaveAnUnboundedVariableToItsOwnRange() {
        assertTrue(UserEnvironmentVariableLimits.isWithinLimits(UNBOUNDED, "6"));
        assertTrue(UserEnvironmentVariableLimits.isWithinLimits(UNBOUNDED, "1000"));
        assertFalse(UserEnvironmentVariableLimits.isWithinLimits(UNBOUNDED, "abc"));
    }

    @Test
    void shouldReportWhichVariablesAreBounded() {
        assertTrue(UserEnvironmentVariableLimits.isBounded(BOUNDED));
        assertFalse(UserEnvironmentVariableLimits.isBounded(UNBOUNDED));
        assertFalse(UserEnvironmentVariableLimits.isBounded(null));
    }

    @Test
    void shouldReportTheRangeForTheMessageShownToTheUser() {
        assertEquals(1, UserEnvironmentVariableLimits.minimum(BOUNDED));
        assertEquals(5, UserEnvironmentVariableLimits.maximum(BOUNDED));
        assertEquals(-1, UserEnvironmentVariableLimits.minimum(UNBOUNDED));
        assertEquals(-1, UserEnvironmentVariableLimits.maximum(UNBOUNDED));
    }
}
