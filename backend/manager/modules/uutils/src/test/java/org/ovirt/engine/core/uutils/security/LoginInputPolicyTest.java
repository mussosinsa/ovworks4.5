package org.ovirt.engine.core.uutils.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.ovirt.engine.core.uutils.security.LoginInputPolicy.Field;
import org.ovirt.engine.core.uutils.security.LoginInputPolicy.Problem;
import org.ovirt.engine.core.uutils.security.LoginInputPolicy.Refusal;

public class LoginInputPolicyTest {

    private static Optional<Problem> userName(String value) {
        return LoginInputPolicy.checkUserName(value).map(Refusal::getProblem);
    }

    private static Optional<Problem> password(String value) {
        return LoginInputPolicy.checkPassword(value).map(Refusal::getProblem);
    }

    @ParameterizedTest
    @ValueSource(strings = { "admin", "admin@internal", "user.name_01", "kim-minsu", "a2345678901234567890" })
    public void acceptsOrdinaryLoginIds(String value) {
        assertEquals(Optional.empty(), userName(value));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "Vm!Xk7pLq2Zt", "P@ssw0rd#2024!", "Door1=Open!", "Color'Red9", "Ab(1)=x<y>", "Q1w2e3r4!@#$%^&*",
        "a2345678901234567890", "Orange#77", "Candy'S9!"
    })
    public void acceptsOrdinaryPasswords(String value) {
        assertEquals(Optional.empty(), password(value));
    }

    @Test
    public void emptyIsLeftToTheLogin() {
        assertEquals(Optional.empty(), userName(null));
        assertEquals(Optional.empty(), password(""));
    }

    @Test
    public void refusesMoreThanTwentyCharacters() {
        assertEquals(Optional.of(Problem.TOO_LONG), userName("a23456789012345678901"));
        assertEquals(Optional.of(Problem.TOO_LONG), password("Vm!Xk7pLq2Zt-Vm!Xk7pL"));
    }

    @ParameterizedTest
    @ValueSource(strings = { "ad|min", "ad;min", "ad:min", "ad`min", "ad min", "admin\t", "ad　min", "ad min" })
    public void refusesForbiddenCharactersInBothFields(String value) {
        assertEquals(Optional.of(Problem.FORBIDDEN_CHARACTER), userName(value));
        assertEquals(Optional.of(Problem.FORBIDDEN_CHARACTER), password(value));
    }

    @ParameterizedTest
    @ValueSource(strings = { "admin'", "a\"b", "a=b", "a<b", "a>b", "a(b", "a)b", "a,b", "a*" })
    public void refusesQuotesAndOperatorsInTheLoginIdOnly(String value) {
        assertEquals(Optional.of(Problem.FORBIDDEN_CHARACTER), userName(value));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "'or'1'='1", "'OR'a'='a", "\"or\"1\"=\"1", "')or('1", "x'or1=1", "admin'--", "'or1=1--",
        "or1=1", "'and'1'='1", "a'='a", "x'xor'y", "admin'/*", "*/x", "1'union(select", "select.from",
        "pg_sleep(5)", "Sleep(10)", "information_schema", "pg_catalog.x", "exec(xp_cmdshell)"
    })
    public void refusesSqlInjection(String value) {
        assertEquals(Optional.of(Problem.SQL_INJECTION), password(value), value);
    }

    @Test
    public void refusesTheExampleOfTheInspection() {
        // ' or 1=1 - refused already for its blank in either field, and for the quote in the ID
        assertTrue(LoginInputPolicy.checkUserName("' or 1=1").isPresent());
        assertTrue(LoginInputPolicy.checkPassword("' or 1=1").isPresent());
        assertEquals(Optional.of(Problem.SQL_INJECTION), password("'or1=1"));
    }

    @Test
    public void checksTheIdBeforeThePassword() {
        Refusal refusal = LoginInputPolicy.check("ad;min", "'or1=1").get();
        assertEquals(Field.USER_NAME, refusal.getField());
        refusal = LoginInputPolicy.check("admin", "'or1=1").get();
        assertEquals(Field.PASSWORD, refusal.getField());
        assertFalse(LoginInputPolicy.check("admin", "Vm!Xk7pLq2Zt").isPresent());
    }

    @Test
    public void messagesNameTheFieldAndNeverTheValue() {
        Refusal refusal = LoginInputPolicy.checkPassword("Secret;Value1").get();
        assertEquals("패스워드에 사용 불가능한 특수문자가 포함되어 있습니다. (| ; : ` 공백)", refusal.getMessage());
        assertFalse(refusal.toString().contains("Secret"));
        assertEquals("아이디는 최대 20자까지 입력할 수 있습니다.",
                LoginInputPolicy.message(Field.USER_NAME, Problem.TOO_LONG));
        assertEquals("아이디에 허용되지 않는 입력(SQL 구문)이 포함되어 있습니다.",
                LoginInputPolicy.message(Field.USER_NAME, Problem.SQL_INJECTION));
    }

    @Test
    public void jsonCannotCloseTheScriptElement() {
        String json = LoginInputPolicy.toJson();
        assertFalse(json.contains("<"));
        assertFalse(json.contains(">"));
        assertTrue(json.startsWith("{\"maxLength\":20,\"forbidden\":\"|;:`\""));
        assertTrue(json.contains("\"userNameForbidden\":\"'\\\"=\\u003c\\u003e(),*\""));
        assertTrue(json.contains("\"PASSWORD\":{\"TOO_LONG\":\"패스워드는 최대 20자까지 입력할 수 있습니다.\""));
    }
}
