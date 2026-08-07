package org.ovirt.engine.core.bll.network.host;


import java.util.Set;
import java.util.stream.Collectors;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.QueriesCommandBase;
import org.ovirt.engine.core.bll.context.EngineContext;
import org.ovirt.engine.core.common.businessentities.network.VdsNetworkInterface;
import org.ovirt.engine.core.common.queries.IdQueryParameters;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.vdsbroker.NetworkImplementationDetailsUtils;

public class GetOutOfSyncHostsForClusterQuery<P extends IdQueryParameters> extends QueriesCommandBase<P> {

    @Inject
    private NetworkImplementationDetailsUtils util;

    public GetOutOfSyncHostsForClusterQuery(P parameters, EngineContext engineContext) {
        super(parameters, engineContext);
    }

    @Override
    protected void executeQueryCommand() {
        Set<Guid> outOfSyncVdsIds = util.getAllInterfacesOutOfSync(getParameters().getId())
            .stream()
            .map(VdsNetworkInterface::getVdsId)
            .collect(Collectors.toSet());

        getQueryReturnValue().setReturnValue(outOfSyncVdsIds);
    }
}
