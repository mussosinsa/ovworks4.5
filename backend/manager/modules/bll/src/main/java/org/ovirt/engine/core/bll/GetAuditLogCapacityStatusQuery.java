package org.ovirt.engine.core.bll;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.context.EngineContext;
import org.ovirt.engine.core.common.queries.QueryParametersBase;

/**
 * How full the storage holding the audit records is.
 *
 * <p>The engine has always watched this and raised an alert when the space ran short. An alert is
 * what an administrator is told once it is already a problem; there was no screen that simply said
 * how full the storage was, so the state could not be looked at, only waited for. This is what such
 * a screen asks.</p>
 *
 * <p>Not a database query. What fills up is a directory on the engine host, and its size is not
 * anywhere in the database - so the answer comes from the component that is already measuring it,
 * {@link AuditLogCapacityMonitor}, rather than from a fresh walk of the directory per request.</p>
 *
 * <p>An administrator query - see the QueryType entry, which carries no QueryAuthType and so
 * defaults to Admin. How much room the records have left, and the path they are kept at, is not
 * something an ordinary user is shown.</p>
 */
public class GetAuditLogCapacityStatusQuery<P extends QueryParametersBase> extends QueriesCommandBase<P> {

    @Inject
    private AuditLogCapacityMonitor capacityMonitor;

    public GetAuditLogCapacityStatusQuery(P parameters, EngineContext engineContext) {
        super(parameters, engineContext);
    }

    @Override
    protected void executeQueryCommand() {
        getQueryReturnValue().setReturnValue(capacityMonitor.getStatus());
    }
}
