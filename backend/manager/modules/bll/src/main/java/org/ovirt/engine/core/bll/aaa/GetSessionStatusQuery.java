package org.ovirt.engine.core.bll.aaa;

import org.ovirt.engine.core.bll.QueriesCommandBase;
import org.ovirt.engine.core.bll.context.EngineContext;
import org.ovirt.engine.core.common.businessentities.aaa.SessionEndReason;
import org.ovirt.engine.core.common.queries.QueryParametersBase;

/**
 * Answers whether a session is still usable and, when it is not, why it stopped being usable.
 *
 * <p>{@code ValidateSession} answers the first half of that already, but it cannot be used for
 * this. It is the query every authenticated request runs, so it refreshes the session it is asked
 * about - which is right there and would be wrong here, where the asking is a client checking on
 * itself. A client that checked once a minute would keep its own session alive forever and the
 * idle timeout would never be reached by anybody who asks.</p>
 *
 * <p>The return value is the reason the session ended, or null while it has not ended. Whether the
 * engine could answer at all is carried separately, by {@code succeeded}: a caller that cannot get
 * an answer must not read that as the session being over, because the difference between "your
 * session is gone" and "the engine could not say" is the difference between logging a user out and
 * leaving them alone.</p>
 */
public class GetSessionStatusQuery<P extends QueryParametersBase> extends QueriesCommandBase<P> {

    public GetSessionStatusQuery(P parameters, EngineContext engineContext) {
        super(parameters, engineContext);
    }

    /** Asking after a session is not using it. See {@link QueriesCommandBase#refreshesSession()}. */
    @Override
    protected boolean refreshesSession() {
        return false;
    }

    @Override
    protected void executeQueryCommand() {
        SessionEndReason reason =
                getSessionDataContainer().getSessionEndReason(getParameters().getSessionId());
        getQueryReturnValue().setReturnValue(reason);
        getQueryReturnValue().setSucceeded(true);
    }
}
