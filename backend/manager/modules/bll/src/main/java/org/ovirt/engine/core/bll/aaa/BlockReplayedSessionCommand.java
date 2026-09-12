package org.ovirt.engine.core.bll.aaa;

import java.util.Collections;
import java.util.List;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.CommandBase;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.action.BlockReplayedSessionParameters;

/**
 * Decides whether a request naming a session that no longer exists is a copy of an older request.
 *
 * <p>It runs for a request nobody has authenticated yet, so it has no user session of its own and
 * asks for none: what it is given is the session identifier the request presented, which is exactly
 * what such a request carries and all there is to judge by. Answering is not a privilege - a caller
 * learns only whether the identifier it already holds names a session that was ended.</p>
 *
 * <p>The audit entry is written where the record lives, in {@code SessionDataContainer}, because the
 * user whose session is being named is not the caller and this command has no user of its own to
 * attribute it to.</p>
 */
public class BlockReplayedSessionCommand<T extends BlockReplayedSessionParameters> extends CommandBase<T> {

    @Inject
    private SessionDataContainer sessionDataContainer;

    public BlockReplayedSessionCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected boolean validate() {
        return true;
    }

    @Override
    protected void executeCommand() {
        setActionReturnValue(sessionDataContainer.isReplayOfEndedSession(
                getParameters().getHttpSessionId(),
                getParameters().getSourceIp(),
                getParameters().getRequestDescription()));
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
