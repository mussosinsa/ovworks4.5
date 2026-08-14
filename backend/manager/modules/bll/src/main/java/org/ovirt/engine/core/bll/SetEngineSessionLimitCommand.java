package org.ovirt.engine.core.bll;

import java.util.Collections;
import java.util.List;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.SetEngineSessionLimitParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.DbUserDao;
import org.ovirt.engine.core.dao.UserProfileDao;

public class SetEngineSessionLimitCommand extends CommandBase<SetEngineSessionLimitParameters> {

    public static final String SESSION_LIMIT_PROPERTY = "CONCURRENT_SESSION_LIMIT"; //$NON-NLS-1$
    private static final int MAX_SESSION_LIMIT = 5;

    private String targetUserName;

    @Inject
    private DbUserDao dbUserDao;

    @Inject
    private UserProfileDao userProfileDao;

    public SetEngineSessionLimitCommand(SetEngineSessionLimitParameters parameters, CommandContext commandContext) {
        super(parameters, commandContext);
    }

    @Override
    protected boolean validate() {
        Guid userId = getParameters().getUserId();
        return userId != null && !Guid.Empty.equals(userId)
                && getParameters().getSessionLimit() > 0
                && getParameters().getSessionLimit() <= MAX_SESSION_LIMIT
                && dbUserDao.get(userId) != null;
    }

    @Override
    protected void executeCommand() {
        try {
            Guid userId = getParameters().getUserId();
            DbUser user = dbUserDao.get(userId);
            targetUserName = user == null ? userId.toString() : user.getLoginName();
            UserProfileProperty existing = userProfileDao.getByName(SESSION_LIMIT_PROPERTY, userId);
            UserProfileProperty property = UserProfileProperty.builder()
                    .withUserId(userId)
                    .withName(SESSION_LIMIT_PROPERTY)
                    .withTypeJson()
                    .withContent(Integer.toString(getParameters().getSessionLimit()))
                    .withPropertyId(existing == null ? Guid.newGuid() : existing.getPropertyId())
                    .build();
            if (existing == null) {
                userProfileDao.save(property);
            } else {
                userProfileDao.update(property);
            }
            setSucceeded(true);
        } catch (RuntimeException exception) {
            log.error("Failed to update concurrent session limit for user {}", getParameters().getUserId(), exception);
            setSucceeded(false);
        }
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        addCustomValue("SessionLimit", Integer.toString(getParameters().getSessionLimit())); //$NON-NLS-1$
        addCustomValue("TargetUserName", targetUserName == null //$NON-NLS-1$
                ? String.valueOf(getParameters().getUserId())
                : targetUserName);
        return getSucceeded()
                ? AuditLogType.USER_SESSION_LIMIT_UPDATED
                : AuditLogType.USER_SESSION_LIMIT_UPDATE_FAILED;
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(Guid.SYSTEM,
                VdcObjectType.System,
                ActionGroup.CONFIGURE_ENGINE));
    }
}
