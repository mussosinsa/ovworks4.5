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
import org.ovirt.engine.core.uutils.crypto.DekEnvelope;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck;

/**
 * Registers, changes or removes the terminal serial a user logs in with.
 *
 * <p>Administrators log in with the serial in config.json. A user logs in with a serial of its own,
 * set here when the user is created or edited: the checks before the login accept any registered
 * serial, and the login itself (CreateUserSessionCommand) refuses a user whose request does not
 * carry that user's serial. An empty serial removes it - the user then cannot log in.</p>
 *
 * <p>The rules: {@code ovworks} and its serial number, 12 to 16 characters, and no two users with
 * the same serial. The serial is kept encrypted under the DEK (see {@link UserClientSerials}); it is
 * never written to the event list or the log.</p>
 */
public class SetUserClientSerialCommand extends CommandBase<SetUserClientSerialParameters> {

    private String targetUserName;
    private boolean removed;
    private String failureReason;

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
            UserProfileProperty legacy = userProfileDao.getByName(UserClientSerials.LEGACY_PROPERTY, userId);
            if (legacy != null) {
                userProfileDao.remove(legacy.getPropertyId());
            }
            if (serial == null) {
                if (existing != null) {
                    userProfileDao.remove(existing.getPropertyId());
                }
            } else {
                if (UserClientSerials.isRegisteredToAnotherUser(
                        userProfileDao.getAllByName(UserClientSerials.PROPERTY), userId, serial)) {
                    refuse("이미 다른 사용자에게 등록된 단말기 시리얼입니다"); //$NON-NLS-1$
                    return;
                }
                // property_content is jsonb: the envelope is stored as a JSON string.
                UserProfileProperty property = UserProfileProperty.builder()
                        .withUserId(userId)
                        .withName(UserClientSerials.PROPERTY)
                        .withTypeJson()
                        .withContent(UserClientSerials.contentFor(serial))
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
            UserClientSerials.writeRegistry(UserClientSerials.envelopes(
                    userProfileDao.getAllByName(UserClientSerials.PROPERTY)));
            setSucceeded(true);
        } catch (DekEnvelope.DekException exception) {
            log.error("Failed to set the terminal serial of user {}: {}", targetUserName, exception.getMessage());
            refuse("DEK로 단말기 시리얼을 암호화할 수 없습니다: " + exception.getMessage()); //$NON-NLS-1$
        } catch (IOException | RuntimeException exception) {
            log.error("Failed to set the terminal serial of user {}: {}", targetUserName, exception.getMessage());
            log.debug("Exception", exception); //$NON-NLS-1$
            refuse(exception.getMessage());
        }
    }

    private void refuse(String reason) {
        failureReason = reason;
        getReturnValue().getExecuteFailedMessages().add(reason);
        setSucceeded(false);
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        addCustomValue("TargetUserName", targetUserName == null //$NON-NLS-1$
                ? String.valueOf(getParameters().getUserId())
                : targetUserName);
        addCustomValue("SerialAction", removed ? "해제" : "등록"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        addCustomValue("FailureReason", failureReason == null ? "-" : failureReason); //$NON-NLS-1$ //$NON-NLS-2$
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
