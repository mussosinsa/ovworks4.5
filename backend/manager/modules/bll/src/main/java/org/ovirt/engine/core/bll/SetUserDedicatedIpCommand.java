package org.ovirt.engine.core.bll;

import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.SetUserDedicatedIpParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.common.utils.ValidationUtils;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.DbUserDao;
import org.ovirt.engine.core.dao.UserProfileDao;
import org.ovirt.engine.core.utils.serialization.json.JsonObjectSerializer;

/**
 * Registers, changes or removes a user's dedicated login IP, kept as a per-user profile property.
 *
 * <p>An empty IP removes the property, so the same command covers register, modify and delete. The
 * login path ({@code CreateUserSessionCommand}) reads the property and refuses a login whose source
 * address does not match it.</p>
 */
public class SetUserDedicatedIpCommand extends CommandBase<SetUserDedicatedIpParameters> {

    /** The per-user profile property that holds the one address the user may log in from. */
    public static final String DEDICATED_LOGIN_IP_PROPERTY = "DEDICATED_LOGIN_IP"; //$NON-NLS-1$

    private static final Pattern IP = Pattern.compile(ValidationUtils.ANY_IP_PATTERN);

    private String targetUserName;

    @Inject
    private DbUserDao dbUserDao;

    @Inject
    private UserProfileDao userProfileDao;

    public SetUserDedicatedIpCommand(SetUserDedicatedIpParameters parameters, CommandContext commandContext) {
        super(parameters, commandContext);
    }

    @Override
    protected boolean validate() {
        Guid userId = getParameters().getUserId();
        if (userId == null || Guid.Empty.equals(userId) || dbUserDao.get(userId) == null) {
            return false;
        }
        String ip = StringUtils.trimToNull(getParameters().getDedicatedIp());
        // Empty removes the restriction; a value must be a single literal IPv4/IPv6 address.
        return ip == null || IP.matcher(ip).matches();
    }

    @Override
    protected void executeCommand() {
        try {
            Guid userId = getParameters().getUserId();
            DbUser user = dbUserDao.get(userId);
            targetUserName = user == null ? userId.toString() : user.getLoginName();
            String ip = StringUtils.trimToNull(getParameters().getDedicatedIp());
            UserProfileProperty existing = userProfileDao.getByName(DEDICATED_LOGIN_IP_PROPERTY, userId);
            if (ip == null) {
                if (existing != null) {
                    userProfileDao.remove(existing.getPropertyId());
                }
                setSucceeded(true);
                return;
            }
            // The property_content column is jsonb, so the value has to be valid JSON: the IP is
            // stored as a JSON string (e.g. "192.168.0.5"), and read back through
            // CreateUserSessionCommand.dedicatedIpFromContent.
            UserProfileProperty property = UserProfileProperty.builder()
                    .withUserId(userId)
                    .withName(DEDICATED_LOGIN_IP_PROPERTY)
                    .withTypeJson()
                    .withContent(new JsonObjectSerializer().serializeUnformattedJson(ip))
                    .withPropertyId(existing == null ? Guid.newGuid() : existing.getPropertyId())
                    .build();
            if (existing == null) {
                userProfileDao.save(property);
            } else {
                userProfileDao.update(property);
            }
            setSucceeded(true);
        } catch (RuntimeException exception) {
            log.error("Failed to set dedicated login IP for user {}", getParameters().getUserId(), exception);
            setSucceeded(false);
        }
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        addCustomValue("DedicatedIp", //$NON-NLS-1$
                StringUtils.defaultIfEmpty(StringUtils.trimToEmpty(getParameters().getDedicatedIp()), "-"));
        addCustomValue("TargetUserName", targetUserName == null //$NON-NLS-1$
                ? String.valueOf(getParameters().getUserId())
                : targetUserName);
        return getSucceeded()
                ? AuditLogType.USER_DEDICATED_IP_UPDATED
                : AuditLogType.USER_DEDICATED_IP_UPDATE_FAILED;
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(Guid.SYSTEM,
                VdcObjectType.System,
                ActionGroup.CONFIGURE_ENGINE));
    }
}
