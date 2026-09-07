package org.ovirt.engine.core.bll.provider;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.CommandBase;
import org.ovirt.engine.core.bll.NonTransactiveCommandAttribute;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.ProviderParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.common.businessentities.Provider;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.provider.ProviderDao;

/**
 * Allows to test that the provider definition allows connecting to the provider and accessing it's API.<br>
 * In case of connection failure, an exception will be thrown.
 *
 * @param <P>
 *            Parameter type.
 */
@NonTransactiveCommandAttribute
public class TestProviderConnectivityCommand<P extends ProviderParameters> extends CommandBase<P> {
    @Inject
    private ProviderProxyFactory providerProxyFactory;

    @Inject
    private ProviderDao providerDao;

    public TestProviderConnectivityCommand(Guid commandId) {
        super(commandId);
    }

    public TestProviderConnectivityCommand(P parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected void executeCommand() {
        ProviderProxy proxy = providerProxyFactory.create(withStoredPassword(getParameters().getProvider()));

        proxy.testConnection();
        setSucceeded(true);
    }

    /**
     * Lets a saved provider be tested without the password being typed again, now that a client is
     * never handed the stored one.
     *
     * <p>The password is only reused when the address has not been changed. This command sends the
     * credential to whatever address the caller passes, keeps no record of it and stores nothing,
     * so reusing a stored password against a new address would hand it to wherever the caller
     * pointed. Testing a moved provider needs the password typed in.
     */
    private Provider<?> withStoredPassword(Provider<?> provider) {
        if (provider == null || provider.getId() == null || provider.getPassword() != null) {
            return provider;
        }
        Provider<?> stored = providerDao.get(provider.getId());
        if (stored != null
                && Objects.equals(stored.getUrl(), provider.getUrl())
                && Objects.equals(stored.getAuthUrl(), provider.getAuthUrl())
                && Objects.equals(stored.getUsername(), provider.getUsername())) {
            ProviderPasswords.resolvePassword(provider, stored);
        }
        return provider;
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(Guid.SYSTEM,
                VdcObjectType.System,
                ActionGroup.CREATE_STORAGE_POOL));
    }

}
