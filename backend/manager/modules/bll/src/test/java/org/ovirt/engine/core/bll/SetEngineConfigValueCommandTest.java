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
            "ENGINE_SSO_USER_LOCK_MAX_FAILURES, 1",
            "ENGINE_SSO_USER_LOCK_MAX_FAILURES, 5",
            "ENGINE_SSO_USER_LOCK_MINUTES, 5",
            "ENGINE_SSO_USER_LOCK_MINUTES, 100000",
            "UserSessionTimeOutInterval, 1",
            "UserSessionTimeOutInterval, 10",
            "ENGINE_SSO_SINGLE_SESSION_POLICY, REPLACE_EXISTING",
            "ENGINE_SSO_SINGLE_SESSION_POLICY, REJECT_NEW",
            "ENGINE_AUDIT_STORAGE_THRESHOLDS, '70,80,90,95'",
            "ENGINE_AUDIT_STORAGE_THRESHOLDS, '1,2,3,99'",
            "ENGINE_AUDIT_DB_DATA_DIR, /var/lib/pgsql/data",
            "ENGINE_AUDIT_DB_DATA_DIR, ''",
            "ENGINE_AUDIT_BACKUP_DIR, /backup/audit"
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
            "ENGINE_SSO_USER_LOCK_MAX_FAILURES, 0",
            "ENGINE_SSO_USER_LOCK_MAX_FAILURES, 6",
            "ENGINE_SSO_USER_LOCK_MINUTES, 4",
            "ENGINE_SSO_USER_LOCK_MINUTES, 100001",
            "UserSessionTimeOutInterval, 0",
            "UserSessionTimeOutInterval, 11",
            "UserSessionTimeOutInterval, invalid",
            "ENGINE_SSO_SINGLE_SESSION_POLICY, invalid",
            "ENGINE_AUDIT_STORAGE_THRESHOLDS, '70,80,90'",
            "ENGINE_AUDIT_STORAGE_THRESHOLDS, '80,70,90,95'",
            "ENGINE_AUDIT_STORAGE_THRESHOLDS, '70,80,90,100'",
            "ENGINE_AUDIT_STORAGE_THRESHOLDS, '0,80,90,95'",
            "ENGINE_AUDIT_STORAGE_THRESHOLDS, '70,80,x,95'",
            "ENGINE_AUDIT_DB_DATA_DIR, relative/path",
            "ENGINE_AUDIT_BACKUP_DIR, /backup/../etc"
    })
    void rejectsSecuritySettingValuesOutsideAllowedRanges(String key, String value) {
        assertNotNull(SetEngineConfigValueCommand.validateEngineConfigValue(key, value));
    }
}
