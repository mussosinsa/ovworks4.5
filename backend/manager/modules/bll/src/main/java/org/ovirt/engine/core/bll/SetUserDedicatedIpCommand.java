package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.bll.aaa.CreateUserSessionCommand;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.SetUserDedicatedIpParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.common.utils.Ipv4AddressUtils;
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
 *
 * <p>The address is also registered with the web server, the same way the terminal IP screen does
 * it ({@link TerminalIpConfigUtils}): the {@code Require ip} list in z-ovirt-engine-proxy.conf turns
 * away anything not on it before the engine sees the login, so a dedicated IP missing from it would
 * never get as far as the check above. Registering adds the address; changing or removing it takes
 * the old address off the list unless another user's dedicated IP is the same address. The web
 * server then reloads gracefully ({@code httpd -k graceful}), without a restart.</p>
 */
public class SetUserDedicatedIpCommand extends CommandBase<SetUserDedicatedIpParameters> {

    /** The per-user profile property that holds the one address the user may log in from. */
    public static final String DEDICATED_LOGIN_IP_PROPERTY = "DEDICATED_LOGIN_IP"; //$NON-NLS-1$

    /**
     * The dedicated login addresses the terminal IP screen does not show: those that only users who
     * are not administrators have. An address an administrator has - alone or shared with users -
     * is shown like any terminal address, so that it is visible as soon as its user becomes one.
     */
    public static Set<String> addressesHiddenFromTerminalScreen(List<UserProfileProperty> properties,
            Predicate<Guid> isAdministrator) {
        Map<String, List<Guid>> usersByAddress = new HashMap<>();
        for (UserProfileProperty property : properties) {
            String address = CreateUserSessionCommand.dedicatedIpFromContent(property.getContent());
            if (address != null) {
                usersByAddress.computeIfAbsent(address.trim(), a -> new ArrayList<>()).add(property.getUserId());
            }
        }
        Set<String> hidden = new HashSet<>();
        usersByAddress.forEach((address, users) -> {
            if (users.stream().noneMatch(isAdministrator)) {
                hidden.add(address);
            }
        });
        return hidden;
    }

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
        // Empty removes the restriction. A value is held to the terminal IP rules, since it goes on
        // the same list: one IPv4 address, not a range, and one a terminal can actually have.
        return ip == null || isAcceptableAddress(ip);
    }

    static boolean isAcceptableAddress(String ip) {
        return Ipv4AddressUtils.isSingleAddress(ip) && Ipv4AddressUtils.isUsableTerminalAddress(ip);
    }

    @Override
    protected void executeCommand() {
        Guid userId = getParameters().getUserId();
        DbUser user = dbUserDao.get(userId);
        targetUserName = user == null ? userId.toString() : user.getLoginName();
        String ip = StringUtils.trimToNull(getParameters().getDedicatedIp());
        UserProfileProperty existing = userProfileDao.getByName(DEDICATED_LOGIN_IP_PROPERTY, userId);
        String oldIp = existing == null ? null : CreateUserSessionCommand.dedicatedIpFromContent(existing.getContent());

        // The web server first: when it cannot be written, nothing is changed at all.
        boolean webServerChanged;
        try {
            webServerChanged = registerWithWebServer(userId, ip, oldIp);
        } catch (IOException | RuntimeException exception) {
            log.error("Failed to register the dedicated login IP of user {} with the web server: {}",
                    userId, exception.getMessage());
            log.debug("Exception", exception); //$NON-NLS-1$
            getReturnValue().getExecuteFailedMessages().add(exception.getMessage());
            setSucceeded(false);
            return;
        }

        try {
            if (ip == null) {
                if (existing != null) {
                    userProfileDao.remove(existing.getPropertyId());
                }
            } else {
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
            }
            setSucceeded(true);
        } catch (RuntimeException exception) {
            log.error("Failed to set dedicated login IP for user {}", userId, exception);
            setSucceeded(false);
        }

        if (webServerChanged) {
            applyToWebServer();
        }
    }

    /**
     * Puts the new address on the web server's terminal list and takes the old one off it, unless
     * another user's dedicated IP is that same address.
     *
     * @return true when the list changed
     */
    private boolean registerWithWebServer(Guid userId, String ip, String oldIp) throws IOException {
        boolean changed = false;
        if (ip != null) {
            changed = TerminalIpConfigUtils.addAddress(ip);
        }
        if (oldIp != null && !oldIp.equals(ip)
                && !isUsedByAnotherUser(userProfileDao.getAllByName(DEDICATED_LOGIN_IP_PROPERTY), userId, oldIp)) {
            changed |= TerminalIpConfigUtils.removeAddress(oldIp);
        }
        return changed;
    }

    /** Whether a user other than {@code userId} has {@code ip} as their dedicated login IP. */
    static boolean isUsedByAnotherUser(List<UserProfileProperty> properties, Guid userId, String ip) {
        for (UserProfileProperty property : properties) {
            if (!userId.equals(property.getUserId())
                    && ip.equals(CreateUserSessionCommand.dedicatedIpFromContent(property.getContent()))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Has the web server apply the list now, without a restart. The list is already written, so a
     * reload that fails is reported but does not undo it: the next reload or restart applies it.
     */
    private void applyToWebServer() {
        try {
            TerminalIpConfigUtils.reloadWebServerGracefully();
        } catch (IOException exception) {
            log.error("Terminal IP list written but the web server could not reload it: {}",
                    exception.getMessage());
            log.debug("Exception", exception); //$NON-NLS-1$
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
