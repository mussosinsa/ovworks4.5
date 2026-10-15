package org.ovirt.engine.core.bll;

import java.io.IOException;

import org.ovirt.engine.core.bll.context.EngineContext;
import org.ovirt.engine.core.common.queries.QueryParametersBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The terminal addresses the terminal screen cannot change or remove: 127.0.0.1 and the engine
 * host's own addresses on the list, one per line. The engine keeps them whatever the screen sends
 * (TerminalIpConfigUtils); the screen asks for them only to say so instead of appearing to remove
 * them.
 */
public class GetTerminalIpProtectedQuery<P extends QueryParametersBase> extends QueriesCommandBase<P> {

    private static final Logger log = LoggerFactory.getLogger(GetTerminalIpProtectedQuery.class);

    public GetTerminalIpProtectedQuery(P parameters, EngineContext engineContext) {
        super(parameters, engineContext);
    }

    @Override
    protected void executeQueryCommand() {
        try {
            getQueryReturnValue().setReturnValue(String.join("\n", TerminalIpConfigUtils.protectedAddresses())); //$NON-NLS-1$
        } catch (IOException ex) {
            log.error("Failed to read the protected terminal IP addresses", ex); //$NON-NLS-1$
            getQueryReturnValue().setReturnValue("127.0.0.1"); //$NON-NLS-1$
        }
    }
}
