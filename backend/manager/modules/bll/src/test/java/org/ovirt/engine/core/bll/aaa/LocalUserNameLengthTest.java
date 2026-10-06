package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.common.businessentities.BusinessEntitiesDefinitions;
import org.ovirt.engine.core.uutils.security.LoginInputPolicy;
import org.ovirt.engine.core.uutils.security.PasswordPolicy;
import org.ovirt.engine.core.uutils.security.PasswordPolicyValidator;
import org.ovirt.engine.core.uutils.security.PasswordPolicyViolation;

/**
 * Adding and editing a local user, and resetting its password, take no more characters than the
 * login page does: 20.
 */
public class LocalUserNameLengthTest {

    private static final String TWENTY = "abcdefghijklmnopqrst";

    @Test
    void theDialogsAndTheLoginPageShareOneLimit() {
        // The GWT dialogs cannot reference uutils, so they carry their own copy of the number.
        assertEquals(20, LoginInputPolicy.MAX_LENGTH);
        assertEquals(LoginInputPolicy.MAX_LENGTH, BusinessEntitiesDefinitions.LOCAL_USER_INPUT_MAX_LENGTH);
    }

    @Test
    void namesUpToTwentyCharactersAreAccepted() {
        assertFalse(LocalUserNameLength.check(TWENTY, TWENTY).isPresent());
        assertFalse(LocalUserNameLength.check(null, "").isPresent());
    }

    @Test
    void aLongerFirstOrLastNameIsRefusedByName() {
        Optional<String> first = LocalUserNameLength.check(TWENTY + "u", "kim");
        assertTrue(first.isPresent());
        assertEquals("이름은(는) 최대 20자까지 입력할 수 있습니다.", first.get());
        assertEquals("성은(는) 최대 20자까지 입력할 수 있습니다.",
                LocalUserNameLength.check("gildong", TWENTY + "u").get());
    }

    @Test
    void theIdLongerThanTwentyIsRefused() {
        assertTrue(LoginInputPolicy.checkUserName(TWENTY + "u").isPresent());
        assertFalse(LoginInputPolicy.checkUserName(TWENTY).isPresent());
    }

    @Test
    void aPasswordLongerThanTwentyIsRefusedOnAddAndReset() {
        // AddLocalUserCommand and ResetUserPasswordCommand both run this validator.
        List<PasswordPolicyViolation> violations = PasswordPolicyValidator.validate(
                new PasswordPolicy(), "Vm!Xk7pLq2Zt-Vm!Xk7pL", "someone");
        assertTrue(violations.stream().anyMatch(v -> v.getRule() == PasswordPolicyViolation.Rule.MAX_LENGTH),
                violations.toString());
    }
}
