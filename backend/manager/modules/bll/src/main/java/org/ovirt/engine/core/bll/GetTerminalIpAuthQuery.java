package org.ovirt.engine.core.bll;

import java.io.IOException;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.context.EngineContext;
import org.ovirt.engine.core.common.queries.QueryParametersBase;
import org.ovirt.engine.core.dao.UserProfileDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The registered terminals, as the terminal screen shows them: the users' dedicated login addresses
 * are on the same list in the web server's configuration but are managed with the users, so they
 * are left out here. SetTerminalIpAuthCommand puts them back when the screen saves its list.
 */
public class GetTerminalIpAuthQuery<P extends QueryParametersBase> extends QueriesCommandBase<P> {

    private static final Logger log = LoggerFactory.getLogger(GetTerminalIpAuthQuery.class);

    @Inject
    private UserProfileDao userProfileDao;

    public GetTerminalIpAuthQuery(P parameters, EngineContext engineContext) {
        super(parameters, engineContext);
    }

    @Override
    protected void executeQueryCommand() {
        try {
            getQueryReturnValue().setReturnValue(TerminalIpConfigUtils.readVisibleRequireIp(
                    SetUserDedicatedIpCommand.dedicatedAddresses(userProfileDao.getAllByName(
                            SetUserDedicatedIpCommand.DEDICATED_LOGIN_IP_PROPERTY))));
        } catch (IOException ex) {
            log.error("Failed to read terminal IP auth config", ex); //$NON-NLS-1$
            getQueryReturnValue().setReturnValue(null);
        }
    }
}
