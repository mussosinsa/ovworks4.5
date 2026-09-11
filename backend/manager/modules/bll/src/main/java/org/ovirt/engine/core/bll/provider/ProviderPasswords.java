/*
 * Copyright oVirt Authors
 * SPDX-License-Identifier: Apache-2.0
*/

package org.ovirt.engine.core.bll.provider;

import java.util.List;

import org.ovirt.engine.core.common.businessentities.Provider;

/**
 * Keeps provider passwords on the server.
 *
 * <p>The data access layer decrypts the password into the entity it returns, so a query that hands
 * that entity to a client puts the password in the response for anyone able to open the browser
 * developer tools - which includes every administrator, read only ones among them. The REST API
 * already leaves the password out of the models it maps; these methods do the same for the
 * queries, and give the commands the rule that makes the missing password harmless.
 */
public class ProviderPasswords {

    private ProviderPasswords() {
    }

    /**
     * Clears the password of a provider on its way to a client.
     *
     * <p>The entity is modified rather than copied, which is safe because the data access layer
     * builds a new instance per row and holds no cache of its own.
     *
     * @return the same provider, for use directly as a query result
     */
    public static Provider<?> clearPassword(Provider<?> provider) {
        if (provider != null) {
            provider.setPassword(null);
        }
        return provider;
    }

    /** Clears the password of every provider on its way to a client. */
    public static List<Provider<?>> clearPasswords(List<Provider<?>> providers) {
        if (providers != null) {
            providers.forEach(ProviderPasswords::clearPassword);
        }
        return providers;
    }

    /**
     * Fills in the password a client could not send back, because it was never given one.
     *
     * <p>A provider that carries no password is one whose password was not being changed, so the
     * stored password stands. A provider that no longer authenticates is a different matter: the
     * missing password is the point, and it is left missing.
     */
    public static void resolvePassword(Provider<?> provider, Provider<?> stored) {
        if (provider != null
                && provider.isRequiringAuthentication()
                && provider.getPassword() == null
                && stored != null) {
            provider.setPassword(stored.getPassword());
        }
    }
}
