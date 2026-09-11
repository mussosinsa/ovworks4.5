package org.ovirt.engine.core.bll.provider;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.common.businessentities.Provider;
import org.ovirt.engine.core.common.businessentities.ProviderType;
import org.ovirt.engine.core.compat.Guid;

class ProviderPasswordsTest {

    private static Provider<?> provider(String name, String password, boolean requiresAuthentication) {
        Provider<?> provider = new Provider<>();
        provider.setId(Guid.newGuid());
        provider.setName(name);
        provider.setType(ProviderType.OPENSTACK_NETWORK);
        provider.setUrl("https://provider.example/api");
        provider.setUsername("admin");
        provider.setPassword(password);
        provider.setRequiringAuthentication(requiresAuthentication);
        return provider;
    }

    @Test
    void shouldClearThePasswordAndKeepEverythingElse() {
        Provider<?> provider = provider("neutron", "s3cret", true);

        Provider<?> result = ProviderPasswords.clearPassword(provider);

        assertAll(
                () -> assertNull(result.getPassword()),
                () -> assertEquals("neutron", result.getName()),
                () -> assertEquals("admin", result.getUsername()),
                () -> assertEquals("https://provider.example/api", result.getUrl()),
                () -> assertSame(provider, result));
    }

    @Test
    void shouldTolerateAProviderThatIsNotThere() {
        assertNull(ProviderPasswords.clearPassword(null));
        assertNull(ProviderPasswords.clearPasswords(null));
    }

    @Test
    void shouldClearThePasswordOfEveryProviderInTheList() {
        List<Provider<?>> providers =
                Arrays.asList(provider("one", "s3cret", true), provider("two", "hunter2", true));

        ProviderPasswords.clearPasswords(providers);

        assertAll(
                () -> assertNull(providers.get(0).getPassword()),
                () -> assertNull(providers.get(1).getPassword()),
                () -> assertEquals("one", providers.get(0).getName()),
                () -> assertEquals("two", providers.get(1).getName()));
    }

    @Test
    void shouldKeepTheStoredPasswordWhenAnUpdateDoesNotCarryOne() {
        Provider<?> incoming = provider("neutron", null, true);
        Provider<?> stored = provider("neutron", "s3cret", true);

        ProviderPasswords.resolvePassword(incoming, stored);

        assertEquals("s3cret", incoming.getPassword());
    }

    @Test
    void shouldKeepTheNewPasswordWhenAnUpdateCarriesOne() {
        Provider<?> incoming = provider("neutron", "brand-new", true);
        Provider<?> stored = provider("neutron", "s3cret", true);

        ProviderPasswords.resolvePassword(incoming, stored);

        assertEquals("brand-new", incoming.getPassword());
    }

    @Test
    void shouldLetAProviderStopAuthenticating() {
        // Turning authentication off clears the password on purpose, so it must not come back.
        Provider<?> incoming = provider("neutron", null, false);
        Provider<?> stored = provider("neutron", "s3cret", true);

        ProviderPasswords.resolvePassword(incoming, stored);

        assertNull(incoming.getPassword());
    }

    @Test
    void shouldLeaveAnEmptyPasswordAlone() {
        // An empty password was typed, not omitted, so it replaces the stored one.
        Provider<?> incoming = provider("neutron", "", true);
        Provider<?> stored = provider("neutron", "s3cret", true);

        ProviderPasswords.resolvePassword(incoming, stored);

        assertEquals("", incoming.getPassword());
    }

    @Test
    void shouldTolerateAProviderThatWasNotStoredYet() {
        Provider<?> incoming = provider("neutron", null, true);

        ProviderPasswords.resolvePassword(incoming, null);

        assertNull(incoming.getPassword());
    }
}
