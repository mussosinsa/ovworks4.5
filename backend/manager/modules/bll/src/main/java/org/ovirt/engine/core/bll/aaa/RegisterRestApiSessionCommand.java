package org.ovirt.engine.core.bll.aaa;

import java.util.Collections;
import java.util.List;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.CommandBase;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.action.RegisterRestApiSessionParameters;

/**
 * Notes which HTTP session carries a REST session, once, as the session is created.
 *
 * <p>Only the servlet container knows that pairing, and only while both are alive. Once the session
 * ends the HTTP session is thrown away, and a request that arrives afterwards presenting the cookie
 * has nothing on it that resolves to an engine session - so unless the pairing was written down
 * beforehand, such a request is indistinguishable from one sent by a client that has yet to log in.
 * Telling those two apart is the whole of what this is for.</p>
 */
public class RegisterRestApiSessionCommand<T extends RegisterRestApiSessionParameters> extends CommandBase<T> {

    @Inject
    private SessionDataContainer sessionDataContainer;

    public RegisterRestApiSessionCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected void executeCommand() {
        sessionDataContainer.setHttpSessionId(
                getParameters().getSessionId(),
                getParameters().getHttpSessionId());
        setSucceeded(true);
    }

    @Override
    protected boolean isUserAuthorizedToRunAction() {
        return true;
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.emptyList();
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return AuditLogType.UNASSIGNED;
    }
}
