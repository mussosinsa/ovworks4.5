package org.ovirt.engine.core.sso.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.net.MalformedURLException;
import java.util.List;

import org.junit.jupiter.api.Test;

class SsoContextTest {

    @Test
    void passwordChangeUrlUsesTheAuthenticationPathWithoutItsConfiguredHost() throws MalformedURLException {
        assertEquals(
                "/ovirt-engine/sso/credentials-change.html",
                SsoContext.buildChangePasswordUrl("https://engine/ovirt-engine/sso"));
    }

    @Test
    void passwordChangeUrlHandlesAuthenticationUrlWithTrailingSlash() throws MalformedURLException {
        assertEquals(
                "/ovirt-engine/sso/credentials-change.html",
                SsoContext.buildChangePasswordUrl("https://engine/ovirt-engine/sso/"));
    }

    @Test
    void registeringNewSessionReplacesPreviousSessionForSameAccount() {
        SsoContext context = new SsoContext();
        SsoSession oldSession = session("old-token", "user-id", "internal");
        SsoSession newSession = session("new-token", "user-id", "internal");

        context.registerSingleUserSession(oldSession);

        assertEquals(List.of(oldSession), context.registerSingleUserSession(newSession));
        assertNull(context.getSsoSession("old-token"));
        assertSame(newSession, context.getSsoSession("new-token"));
    }

    @Test
    void sessionsForDifferentAccountsRemainActive() {
        SsoContext context = new SsoContext();
        SsoSession first = session("first-token", "first-user", "internal");
        SsoSession second = session("second-token", "second-user", "internal");

        context.registerSingleUserSession(first);

        assertEquals(List.of(), context.registerSingleUserSession(second));
        assertSame(first, context.getSsoSession("first-token"));
        assertSame(second, context.getSsoSession("second-token"));
    }

    @Test
    void reauthenticationOfSameSessionRemovesItsStaleToken() {
        SsoContext context = new SsoContext();
        SsoSession session = session("old-token", "user-id", "internal");
        context.registerSingleUserSession(session);

        session.setAccessToken("new-token");

        assertEquals(List.of(), context.registerSingleUserSession(session));
        assertNull(context.getSsoSession("old-token"));
        assertSame(session, context.getSsoSession("new-token"));
    }

    private static SsoSession session(String token, String userId, String profile) {
        SsoSession session = new SsoSession();
        session.setAccessToken(token);
        session.setUserId(userId);
        session.setProfile(profile);
        return session;
    }
}
