package org.ovirt.engine.core.bll.aaa;

import java.util.Collections;
import java.util.List;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.CommandBase;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.action.SetSesssionSoftLimitCommandParameters;

public class SetSesssionSoftLimitCommand<T extends SetSesssionSoftLimitCommandParameters> extends CommandBase<T> {

    @Inject
    private SessionDataContainer sessionDataContainer;

    public SetSesssionSoftLimitCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected void executeCommand() {
        if (sessionDataContainer.isSessionExists(getParameters().getSessionId())) {
            int requested = getParameters().getSoftLimit();
            int applied = sessionDataContainer.setSoftLimitInterval(getParameters().getSessionId(), requested);
            if (applied != requested) {
                log.warn("Requested session timeout of {} minutes exceeds UserSessionTimeOutInterval; "
                        + "the session will time out after {} minutes instead.", requested, applied);
            }
            // the caller sets the timeout of its own HTTP session from this, so that the two do not
            // outlive one another
            setActionReturnValue(applied);
            setSucceeded(true);
        } else {
            setSucceeded(false);
        }
    }

    @Override
    protected boolean isUserAuthorizedToRunAction() {
        return true;
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.emptyList();
    }

}
