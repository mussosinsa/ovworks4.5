package org.ovirt.engine.core.sso.api;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.MalformedURLException;

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
}
