package org.ovirt.engine.core.sso.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class UserLoginLockoutServiceTest {

    @Test
    void takesTheLoginNameBackOutOfThePrincipalKey() {
        assertEquals("user01", UserLoginLockoutService.loginNameOf("user01@internal"));
    }

    @Test
    void keepsAnAtSignThatBelongsToTheLoginName() {
        assertEquals("user01@example.com",
                UserLoginLockoutService.loginNameOf("user01@example.com@internal"));
    }

    @Test
    void leavesAKeyWithoutAProfileAlone() {
        assertEquals("user01", UserLoginLockoutService.loginNameOf("user01"));
    }
}
