package org.ovirt.engine.core.uutils.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

public class PasswordPolicyValidatorTest {

    private static List<PasswordPolicyViolation.Rule> rules(List<PasswordPolicyViolation> violations) {
        return violations.stream().map(PasswordPolicyViolation::getRule).collect(Collectors.toList());
    }

    @Test
    public void acceptsPasswordSatisfyingTheDefaultPolicy() {
        List<PasswordPolicyViolation> violations =
                PasswordPolicyValidator.validate(new PasswordPolicy(), "Vm!Xk7pLq2Zt", "admin");
        assertTrue(violations.isEmpty(), "unexpected violations: " + violations);
    }

    @Test
    public void rejectsPasswordShorterThanTwelveCharacters() {
        List<PasswordPolicyViolation> violations =
                PasswordPolicyValidator.validate(new PasswordPolicy(), "Vm!Xk7pL", "admin");
        assertTrue(rules(violations).contains(PasswordPolicyViolation.Rule.MIN_LENGTH));
    }

    @Test
    public void reportsEveryMissingCharacterClass() {
        List<PasswordPolicyViolation> violations =
                PasswordPolicyValidator.validate(new PasswordPolicy(), "kxmpvtwnbjhr", "admin");
        List<PasswordPolicyViolation.Rule> violated = rules(violations);
        assertTrue(violated.contains(PasswordPolicyViolation.Rule.UPPERCASE));
        assertTrue(violated.contains(PasswordPolicyViolation.Rule.DIGIT));
        assertTrue(violated.contains(PasswordPolicyViolation.Rule.SPECIAL));
        assertFalse(violated.contains(PasswordPolicyViolation.Rule.LOWERCASE));
    }

    @Test
    public void characterClassChecksCanBeDisabled() {
        PasswordPolicy policy = new PasswordPolicy()
                .setRequireUppercase(false)
                .setRequireDigit(false)
                .setRequireSpecial(false);
        assertTrue(PasswordPolicyValidator.validate(policy, "kxmpvtwnbjhr", "admin").isEmpty());
    }

    @Test
    public void rejectsPasswordEqualToUserIdIgnoringCase() {
        PasswordPolicy policy = new PasswordPolicy()
                .setRequireUppercase(false)
                .setRequireLowercase(false)
                .setRequireDigit(false)
                .setRequireSpecial(false)
                .setForbidRepeated(false)
                .setForbidSequential(false)
                .setMinLength(1);
        assertEquals(
                Collections.singletonList(PasswordPolicyViolation.Rule.SAME_AS_USER_ID),
                rules(PasswordPolicyValidator.validate(policy, "AdMiNuser", "adminuser")));
        // the local part of name@profile is the same identity
        assertEquals(
                Collections.singletonList(PasswordPolicyViolation.Rule.SAME_AS_USER_ID),
                rules(PasswordPolicyValidator.validate(policy, "adminuser", "adminuser@internal")));
    }

    @Test
    public void allowsPasswordThatMerelyContainsTheUserId() {
        // only equality is forbidden, containment used to be rejected and was too strict
        List<PasswordPolicyViolation> violations =
                PasswordPolicyValidator.validate(new PasswordPolicy(), "Vm!Xkadmin7pLq2Zt", "admin");
        assertFalse(rules(violations).contains(PasswordPolicyViolation.Rule.SAME_AS_USER_ID));
    }

    @Test
    public void rejectsRepeatedCharactersAndRepeatedPatterns() {
        PasswordPolicy policy = new PasswordPolicy().setForbidSequential(false);
        assertTrue(rules(PasswordPolicyValidator.validate(policy, "Vm!Xkaaa7pLq2Zt", "admin"))
                .contains(PasswordPolicyViolation.Rule.REPEATED_CHARACTERS));
        assertTrue(rules(PasswordPolicyValidator.validate(policy, "Vm!Xkpqpq7Lq2Zt", "admin"))
                .contains(PasswordPolicyViolation.Rule.REPEATED_CHARACTERS));
    }

    @Test
    public void rejectsFourSequentialCharacters() {
        PasswordPolicy policy = new PasswordPolicy().setForbidRepeated(false);
        // digits, forward
        assertTrue(rules(PasswordPolicyValidator.validate(policy, "Vm!Xk1234pLqZt", "admin"))
                .contains(PasswordPolicyViolation.Rule.SEQUENTIAL_CHARACTERS));
        // alphabet, backward
        assertTrue(rules(PasswordPolicyValidator.validate(policy, "Vm!X7dcbapLqZt", "admin"))
                .contains(PasswordPolicyViolation.Rule.SEQUENTIAL_CHARACTERS));
        // keyboard row
        assertTrue(rules(PasswordPolicyValidator.validate(policy, "Vm!X7asdfpLqZt", "admin"))
                .contains(PasswordPolicyViolation.Rule.SEQUENTIAL_CHARACTERS));
        // three in a row is still accepted with the default sequence length of four
        assertFalse(rules(PasswordPolicyValidator.validate(policy, "Vm!X7asdpLqZt", "admin"))
                .contains(PasswordPolicyViolation.Rule.SEQUENTIAL_CHARACTERS));
    }

    @Test
    public void optionalChecksCanBeDisabledIndividually() {
        PasswordPolicy policy = new PasswordPolicy()
                .setForbidRepeated(false)
                .setForbidSequential(false);
        assertTrue(PasswordPolicyValidator.validate(policy, "Vm!Xkaaa1234Zt", "admin").isEmpty());
    }

    @Test
    public void rejectsThePreviousPassword() {
        Instant now = Instant.now();
        PasswordHistoryEntry previous =
                new PasswordHistoryEntry(PasswordHistoryCryptor.hash("Vm!Xk7pLq2Zt"), now.minus(1, ChronoUnit.DAYS));

        Optional<PasswordPolicyViolation> violation = PasswordPolicyValidator.validateHistory(
                new PasswordPolicy(), "Vm!Xk7pLq2Zt", Collections.singletonList(previous), now);

        assertTrue(violation.isPresent());
        assertEquals(PasswordPolicyViolation.Rule.PREVIOUS_PASSWORD, violation.get().getRule());
    }

    @Test
    public void rejectsPasswordUsedWithinTheConfiguredWindow() {
        Instant now = Instant.now();
        List<PasswordHistoryEntry> history = Arrays.asList(
                new PasswordHistoryEntry(PasswordHistoryCryptor.hash("Nb#Yt4wRm8Vs"), now.minus(1, ChronoUnit.DAYS)),
                new PasswordHistoryEntry(PasswordHistoryCryptor.hash("Vm!Xk7pLq2Zt"), now.minus(40, ChronoUnit.DAYS)));

        Optional<PasswordPolicyViolation> violation =
                PasswordPolicyValidator.validateHistory(new PasswordPolicy(), "Vm!Xk7pLq2Zt", history, now);

        assertTrue(violation.isPresent());
        assertEquals(PasswordPolicyViolation.Rule.PASSWORD_HISTORY, violation.get().getRule());
    }

    @Test
    public void acceptsPasswordUsedBeforeTheConfiguredWindow() {
        Instant now = Instant.now();
        List<PasswordHistoryEntry> history = Arrays.asList(
                new PasswordHistoryEntry(PasswordHistoryCryptor.hash("Nb#Yt4wRm8Vs"), now.minus(1, ChronoUnit.DAYS)),
                new PasswordHistoryEntry(PasswordHistoryCryptor.hash("Vm!Xk7pLq2Zt"), now.minus(200, ChronoUnit.DAYS)));

        assertFalse(PasswordPolicyValidator
                .validateHistory(new PasswordPolicy(), "Vm!Xk7pLq2Zt", history, now)
                .isPresent());
    }

    @Test
    public void hashedHistoryEntryMatchesOnlyItsOwnPassword() {
        String encoded = PasswordHistoryCryptor.hash("Vm!Xk7pLq2Zt");
        assertTrue(PasswordHistoryCryptor.matches("Vm!Xk7pLq2Zt", encoded));
        assertFalse(PasswordHistoryCryptor.matches("Vm!Xk7pLq2Zu", encoded));
        assertFalse(PasswordHistoryCryptor.matches("Vm!Xk7pLq2Zt", "not-an-encoded-hash"));
    }

    @Test
    public void principalKeyIgnoresTheAuthzSuffixAndCase() {
        assertEquals("admin@internal", PasswordHistoryCryptor.principalKey("admin", "internal-authz"));
        assertEquals("admin@internal", PasswordHistoryCryptor.principalKey("Admin", "Internal"));
        assertEquals("admin@internal", PasswordHistoryCryptor.principalKey("admin@internal", "internal-authz"));
    }
}
