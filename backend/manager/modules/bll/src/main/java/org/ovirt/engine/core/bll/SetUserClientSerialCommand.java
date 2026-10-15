package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.SetUserClientSerialParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.DbUserDao;
import org.ovirt.engine.core.dao.UserProfileDao;
import org.ovirt.engine.core.utils.serialization.json.JsonObjectSerializer;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck;

/**
 * Registers, changes or removes the terminal serial a user logs in with.
 *
 * <p>Administrators log in with the serial in config.json. A user logs in with a serial of its own,
 * set here when the user is created or edited: the checks before the login accept any registered
 * serial, and the login itself (CreateUserSessionCommand) refuses a user whose request does not
 * carry that user's serial. An empty serial removes it - the user then cannot log in.</p>
 *
 * <p>The serial is kept as its SHA-256 digest (see {@link UserClientSerials}); neither the serial
 * nor the digest is written to the event list or the log.</p>
 */
public class SetUserClientSerialCommand extends CommandBase<SetUserClientSerialParameters> {

    private String targetUserName;
    private boolean removed;

    @Inject
    private DbUserDao dbUserDao;

    @Inject
    private UserProfileDao userProfileDao;

    public SetUserClientSerialCommand(SetUserClientSerialParameters parameters, CommandContext commandContext) {
        super(parameters, commandContext);
    }

    @Override
    protected boolean validate() {
        Guid userId = getParameters().getUserId();
        if (userId == null || Guid.Empty.equals(userId) || dbUserDao.get(userId) == null) {
            return false;
        }
        String serial = StringUtils.trimToNull(getParameters().getClientSerial());
        return serial == null || ClientSerialCheck.isAcceptableSerial(serial);
    }

    @Override
    protected void executeCommand() {
        Guid userId = getParameters().getUserId();
        DbUser user = dbUserDao.get(userId);
        targetUserName = user == null ? userId.toString() : user.getLoginName();
        String serial = StringUtils.trimToNull(getParameters().getClientSerial());
        removed = serial == null;
        UserProfileProperty existing = userProfileDao.getByName(UserClientSerials.PROPERTY, userId);
        try {
            if (serial == null) {
                if (existing != null) {
                    userProfileDao.remove(existing.getPropertyId());
                }
            } else {
                // property_content is jsonb: the digest is stored as a JSON string.
                UserProfileProperty property = UserProfileProperty.builder()
                        .withUserId(userId)
                        .withName(UserClientSerials.PROPERTY)
                        .withTypeJson()
                        .withContent(new JsonObjectSerializer().serializeUnformattedJson(
                                ClientSerialCheck.digest(serial)))
                        .withPropertyId(existing == null ? Guid.newGuid() : existing.getPropertyId())
                        .build();
                if (existing == null) {
                    userProfileDao.save(property);
                } else {
                    userProfileDao.update(property);
                }
            }
            // Within the transaction: a list that cannot be written fails the command and so undoes
            // the change above, keeping the two the same.
            UserClientSerials.writeRegistry(UserClientSerials.digests(
                    userProfileDao.getAllByName(UserClientSerials.PROPERTY)));
            setSucceeded(true);
        } catch (IOException | RuntimeException exception) {
            log.error("Failed to set the terminal serial of user {}: {}", targetUserName, exception.getMessage());
            log.debug("Exception", exception); //$NON-NLS-1$
            getReturnValue().getExecuteFailedMessages().add(exception.getMessage());
            setSucceeded(false);
        }
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        addCustomValue("TargetUserName", targetUserName == null //$NON-NLS-1$
                ? String.valueOf(getParameters().getUserId())
                : targetUserName);
        addCustomValue("SerialAction", removed ? "해제" : "등록"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        return getSucceeded()
                ? AuditLogType.USER_CLIENT_SERIAL_UPDATED
                : AuditLogType.USER_CLIENT_SERIAL_UPDATE_FAILED;
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(Guid.SYSTEM,
                VdcObjectType.System,
                ActionGroup.CONFIGURE_ENGINE));
    }
}
