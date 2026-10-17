// Modified by 새올정보기술 for OV-Works (2026). Changes against oVirt Engine 4.5.6: docs/ovworks-source-change-statement.md
package org.ovirt.engine.core.bll.provider;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.QueriesCommandBase;
import org.ovirt.engine.core.bll.context.EngineContext;
import org.ovirt.engine.core.common.businessentities.ProviderType;
import org.ovirt.engine.core.common.queries.GetAllProvidersParameters;
import org.ovirt.engine.core.dao.provider.ProviderDao;

public class GetAllProvidersQuery<P extends GetAllProvidersParameters> extends QueriesCommandBase<P> {
    @Inject
    private ProviderDao providerDao;

    public GetAllProvidersQuery(P parameters, EngineContext engineContext) {
        super(parameters, engineContext);
    }

    @Override
    protected void executeQueryCommand() {
        ProviderType[] providerTypes = getParameters().getProviderTypes();

        if (providerTypes == null) {
            setReturnValue(ProviderPasswords.clearPasswords(providerDao.getAll()));
        } else {
            setReturnValue(ProviderPasswords.clearPasswords(providerDao.getAllByTypes(providerTypes)));
        }
    }
}
