package org.ovirt.engine.core.bll;

import java.io.IOException;

import org.ovirt.engine.core.bll.context.EngineContext;
import org.ovirt.engine.core.common.queries.QueryParametersBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GetTerminalAuthSerialQuery<P extends QueryParametersBase> extends QueriesCommandBase<P> {

    private static final Logger log = LoggerFactory.getLogger(GetTerminalAuthSerialQuery.class);

    public GetTerminalAuthSerialQuery(P parameters, EngineContext engineContext) {
        super(parameters, engineContext);
    }

    @Override
    protected void executeQueryCommand() {
        try {
            getQueryReturnValue().setReturnValue(TerminalAuthConfigUtils.readSerialNumber());
        } catch (IOException ex) {
            log.error("Failed to read terminal auth serial number", ex); //$NON-NLS-1$
            getQueryReturnValue().setReturnValue(null);
        }
    }
}
