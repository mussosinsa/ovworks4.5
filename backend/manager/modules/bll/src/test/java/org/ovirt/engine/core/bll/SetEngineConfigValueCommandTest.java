package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class SetEngineConfigValueCommandTest {

    @ParameterizedTest
    @CsvSource({
            "ENGINE_SSO_ADMIN_LOCK_MAX_FAILURES, 1",
            "ENGINE_SSO_ADMIN_LOCK_MAX_FAILURES, 5",
            "ENGINE_SSO_ADMIN_LOCK_MINUTES, 5",
            "ENGINE_SSO_ADMIN_LOCK_MINUTES, 100000",
            "UserSessionTimeOutInterval, 1",
            "UserSessionTimeOutInterval, 10"
    })
    void acceptsSecuritySettingBoundaryValues(String key, String value) {
        assertNull(SetEngineConfigValueCommand.validateEngineConfigValue(key, value));
    }

    @ParameterizedTest
    @CsvSource({
            "ENGINE_SSO_ADMIN_LOCK_MAX_FAILURES, 0",
            "ENGINE_SSO_ADMIN_LOCK_MAX_FAILURES, 6",
            "ENGINE_SSO_ADMIN_LOCK_MINUTES, 4",
            "ENGINE_SSO_ADMIN_LOCK_MINUTES, 100001",
            "UserSessionTimeOutInterval, 0",
            "UserSessionTimeOutInterval, 11",
            "UserSessionTimeOutInterval, invalid"
    })
    void rejectsSecuritySettingValuesOutsideAllowedRanges(String key, String value) {
        assertNotNull(SetEngineConfigValueCommand.validateEngineConfigValue(key, value));
    }
}
