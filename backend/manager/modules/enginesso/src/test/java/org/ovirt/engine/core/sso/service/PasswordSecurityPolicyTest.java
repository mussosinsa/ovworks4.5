package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

public class PasswordSecurityPolicyTest {

    private final Map<String, String> settings = new HashMap<>();

    @Test
    public void acceptsDefaultCompliantPassword() {
        assertNull(validate("admin", "Previous1!xy", "Secure9!Value"));
    }

    @Test
    public void rejectsUsernameIgnoringCase() {
        assertNotNull(validate("Secure9!Value", "Previous1!xy", "secure9!value"));
    }

    @Test
    public void rejectsPreviousPassword() {
        assertNotNull(validate("admin", "Secure9!Value", "Secure9!Value"));
    }

    @Test
    public void requiresEachCharacterTypeByDefault() {
        assertNotNull(validate("admin", "Previous1!xy", "secure9!value"));
        assertNotNull(validate("admin", "Previous1!xy", "SECURE9!VALUE"));
        assertNotNull(validate("admin", "Previous1!xy", "Secure!Valuex"));
        assertNotNull(validate("admin", "Previous1!xy", "Secure9Valuex"));
    }

    @Test
    public void doesNotAllowMinimumLengthBelowTwelve() {
        settings.put(PasswordSecurityPolicy.MIN_LENGTH, "6"); //$NON-NLS-1$

        assertNotNull(validate("admin", "Previous1!xy", "Short1!a"));
    }

    @Test
    public void rejectsRepeatedAndSequentialPatterns() {
        assertNotNull(validate("admin", "Previous1!xy", "SecureAAA9!xy"));
        assertNotNull(validate("admin", "Previous1!xy", "SecureAbab9!"));
        assertNotNull(validate("admin", "Previous1!xy", "Secure1234!A"));
        assertNotNull(validate("admin", "Previous1!xy", "Secure4321!A"));
        assertNotNull(validate("admin", "Previous1!xy", "SecureQwer9!"));
        assertNotNull(validate("admin", "Previous1!xy", "SecureRewq9!"));
    }

    @Test
    public void allowsOptionalRulesToBeDisabled() {
        settings.put(PasswordSecurityPolicy.REQUIRE_UPPERCASE, "false");
        settings.put(PasswordSecurityPolicy.REQUIRE_LOWERCASE, "false");
        settings.put(PasswordSecurityPolicy.REQUIRE_DIGIT, "false");
        settings.put(PasswordSecurityPolicy.REQUIRE_SPECIAL, "false");
        settings.put(PasswordSecurityPolicy.REJECT_REPEATED, "false");
        settings.put(PasswordSecurityPolicy.REJECT_SEQUENTIAL, "false");
        settings.put(PasswordSecurityPolicy.REJECT_PREVIOUS, "false");

        assertNull(validate("admin", "samepassword", "samepassword"));
    }

    @Test
    public void allowsCharacterClassRulesToBeConfiguredIndependently() {
        settings.put(PasswordSecurityPolicy.REQUIRE_UPPERCASE, "false");
        assertNull(validate("admin", "Previous1!xy", "secure9!value"));

        settings.clear();
        settings.put(PasswordSecurityPolicy.REQUIRE_LOWERCASE, "false");
        assertNull(validate("admin", "Previous1!xy", "SECURE9!VALUE"));

        settings.clear();
        settings.put(PasswordSecurityPolicy.REQUIRE_DIGIT, "false");
        assertNull(validate("admin", "Previous1!xy", "Secure!Valuex"));

        settings.clear();
        settings.put(PasswordSecurityPolicy.REQUIRE_SPECIAL, "false");
        assertNull(validate("admin", "Previous1!xy", "Secure9Valuex"));
    }

    private String validate(String username, String previousPassword, String newPassword) {
        return PasswordSecurityPolicy.validate(username, previousPassword, newPassword, settings::get);
    }
}
