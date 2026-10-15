package org.ovirt.engine.core.bll.aaa;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.api.extensions.ExtKey;
import org.ovirt.engine.api.extensions.ExtMap;
import org.ovirt.engine.api.extensions.aaa.Authz;
import org.ovirt.engine.core.aaa.AuthenticationProfile;
import org.ovirt.engine.core.aaa.AuthenticationProfileRepository;
import org.ovirt.engine.core.aaa.CreateUserSessionsError;
import org.ovirt.engine.core.bll.CommandBase;
import org.ovirt.engine.core.bll.NonTransactiveCommandAttribute;
import org.ovirt.engine.core.bll.PredefinedRoles;
import org.ovirt.engine.core.bll.SetEngineSessionLimitCommand;
import org.ovirt.engine.core.bll.SetUserDedicatedIpCommand;
import org.ovirt.engine.core.bll.UserClientSerials;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.CreateUserSessionParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.common.businessentities.Role;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;
import org.ovirt.engine.core.common.businessentities.aaa.DbGroup;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogableImpl;
import org.ovirt.engine.core.dao.DbGroupDao;
import org.ovirt.engine.core.dao.DbUserDao;
import org.ovirt.engine.core.dao.PermissionDao;
import org.ovirt.engine.core.dao.RoleDao;
import org.ovirt.engine.core.dao.UserProfileDao;
import org.ovirt.engine.core.utils.EngineLocalConfig;
import org.ovirt.engine.core.utils.SerializationFactory;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck.Refusal;

@NonTransactiveCommandAttribute
public class CreateUserSessionCommand<T extends CreateUserSessionParameters> extends CommandBase<T> {
    private static final Guid BOTTOM_OBJECT_ID = new Guid("BBB00000-0000-0000-0000-123456789BBB");
    private static final int UNLIMITED_SESSIONS = -1;
    private final int maxUserSessions;

    @Inject
    private SessionDataContainer sessionDataContainer;
    @Inject
    private PermissionDao permissionDao;
    @Inject
    private DbUserDao dbUserDao;
    @Inject
    private DbGroupDao dbGroupDao;
    @Inject
    private RoleDao roleDao;
    @Inject
    private UserProfileDao userProfileDao;

    private static final String UNKNOWN = "UNKNOWN";
    private static final String OVIRT_ADMINISTRATOR = "ovirt-administrator";
    private static final String INTERNAL_AUTHZ = "internal-authz";
    static final String REASON_DEDICATED_IP_MISMATCH = "전용 접속 IP 불일치"; //$NON-NLS-1$
    static final String REASON_DEDICATED_IP_NOT_REGISTERED = "전용 접속 IP 미등록"; //$NON-NLS-1$
    static final String NO_DEDICATED_IP = "없음"; //$NON-NLS-1$

    private String sessionId;
    private String sourceIp;
    private String loginDeniedReason;
    private String dedicatedIp;
    private String serialDeniedReason;
    private boolean unregisteredSuperUser;

    public CreateUserSessionCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
        maxUserSessions = EngineLocalConfig.getInstance().getInteger("ENGINE_MAX_USER_SESSIONS");
    }

    private DbUser buildUser(T params, String authzName) {
        boolean externalSsoEnabled = EngineLocalConfig.getInstance().getBoolean("ENGINE_SSO_ENABLE_EXTERNAL_SSO");
        DbUser dbUser = externalSsoEnabled ?
                dbUserDao.getByUsernameAndDomain(params.getPrincipalName(), authzName) :
                dbUserDao.getByExternalId(authzName, params.getPrincipalId());
        // AddLocalUserCommand has to create the engine record before the user logs in, but at that point the JDBC
        // extension's generated principal ID isn't available and the login name is stored as a temporary external ID.
        // Reuse that record on first login instead of inserting a second row for the real principal ID.
        if (dbUser == null && isLocallyAddedUser(params, authzName)) {
            DbUser localUser = dbUserDao.getByUsernameAndDomain(params.getPrincipalName(), authzName);
            if (localUser != null && Objects.equals(localUser.getExternalId(), params.getPrincipalName())) {
                dbUser = localUser;
            }
        }
        DbUser user = new DbUser(dbUser);
        user.setId(dbUser == null ? Guid.newGuid() : dbUser.getId());
        user.setExternalId(dbUser == null && externalSsoEnabled ? Guid.newGuid().toString() : params.getPrincipalId());
        user.setDomain(authzName);
        user.setEmail(params.getEmail());
        user.setFirstName(params.getFirstName());
        user.setLastName(params.getLastName());
        user.setNamespace(params.getNamespace());
        user.setLoginName(params.getPrincipalName());
        List<Guid> groupIds = new ArrayList<>();
        Map<String, ExtMap> groupRecords = new HashMap<>();
        flatGroups((Collection<ExtMap>) params.getGroupIds(), groupRecords);
        for (Map.Entry<String, ExtMap> group: groupRecords.entrySet()) {
            String name = group.getValue().get(Authz.GroupRecord.NAME);
            // The domain is empty for predefined ovirt-administrator group
            String domain = name.equals(OVIRT_ADMINISTRATOR) ? "" : authzName;
            // If external sso integration is enabled we retrieve the group by their name and domain. We do not have
            // the external id for the groups in the OpenID Connect claim set.
            DbGroup dbGroup = externalSsoEnabled ?
                    dbGroupDao.getByNameAndDomain(name, domain) :
                    dbGroupDao.getByExternalId(authzName, group.getKey());
            if (dbGroup != null) {
                dbGroup.setName(name);
                dbGroupDao.update(dbGroup);
                groupIds.add(dbGroup.getId());
            }
        }
        user.setGroupIds(groupIds);
        user.setAdmin(
            !roleDao.getAnyAdminRoleForUserAndGroups(
                user.getId(),
                StringUtils.join(user.getGroupIds(), ",")
            ).isEmpty()
        );

        if (dbUser == null) {
            dbUserDao.save(user);
        } else if (!dbUser.equals(user)) {
            dbUserDao.update(user);
        }
        return user;
    }

    private boolean isLocallyAddedUser(T params, String authzName) {
        return INTERNAL_AUTHZ.equals(authzName)
                && !Objects.equals(params.getPrincipalId(), params.getPrincipalName());
    }

    @Override
    protected void executeCommand() {
        final AuthenticationProfile profile = AuthenticationProfileRepository.getInstance()
                .getProfile(getParameters().getProfileName());
        sourceIp = getParameters().getSourceIp();
        if (profile == null) {
            setSucceeded(false);
        } else {
            final DbUser user = buildUser(getParameters(), profile.getAuthzName());
            int effectiveMaxUserSessions = resolveSessionLimit(
                    userProfileDao.getByName(SetEngineSessionLimitCommand.SESSION_LIMIT_PROPERTY, user.getId()),
                    maxUserSessions);
            List<Role> adminRoles = roleDao.getAnyAdminRoleForUserAndGroups(user.getId(),
                    StringUtils.join(user.getGroupIds(), ","));
            boolean isAdmin = !adminRoles.isEmpty();
            boolean isSuperUser = adminRoles.stream()
                    .anyMatch(role -> PredefinedRoles.SUPER_USER.getId().equals(role.getId()));
            user.setAdmin(isAdmin);
            setCurrentUser(user);
            setUserName(String.format("%s@%s", getCurrentUser().getLoginName(), getCurrentUser().getDomain()));

            if (getParameters().isAdminRequired() && !isAdmin) {
                setActionReturnValue(CreateUserSessionsError.USER_NOT_AUTHORIZED);
                setSucceeded(false);
            } else if (permissionDao.getEntityPermissionsForUserAndGroups(user.getId(),
                    StringUtils.join(user.getGroupIds(), ","),
                    ActionGroup.LOGIN,
                    BOTTOM_OBJECT_ID,
                    VdcObjectType.Bottom,
                    true) == null) {
                setActionReturnValue(CreateUserSessionsError.USER_NOT_AUTHORIZED);
                setSucceeded(false);
            } else if (effectiveMaxUserSessions != UNLIMITED_SESSIONS
                    && sessionDataContainer.getNumUserSessions(user) >= effectiveMaxUserSessions) {
                setActionReturnValue(CreateUserSessionsError.NUM_OF_SESSIONS_EXCEEDED);
                addCustomValue("MaxUserSessions", String.valueOf(effectiveMaxUserSessions)); //$NON-NLS-1$
                setSucceeded(false);
            } else if (isLoginIpDenied(user, profile, isSuperUser)) {
                setActionReturnValue(CreateUserSessionsError.LOGIN_IP_NOT_ALLOWED);
                setSucceeded(false);
            } else if (isClientSerialDenied(user, profile, isAdmin)) {
                setActionReturnValue(CreateUserSessionsError.CLIENT_SERIAL_NOT_ALLOWED);
                setSucceeded(false);
            } else {
                createSession(user, profile, isSuperUser);
            }
        }
    }

    /**
     * Opens the session, unless the super-user seat is taken.
     *
     * <p>The seat is claimed against the session id before the session is otherwise built, so that
     * a login refused for it leaves nothing behind. The claim decides and records in one step, so
     * two super users logging in together cannot both be told the seat was free.</p>
     */
    private void createSession(DbUser user, AuthenticationProfile profile, boolean isSuperUser) {
        String engineSessionId = sessionDataContainer.generateEngineSessionId();
        DbUser activeSuperUser = isSuperUser
                ? sessionDataContainer.claimSuperUserSession(engineSessionId, user)
                : null;
        if (activeSuperUser != null) {
            setActionReturnValue(CreateUserSessionsError.SUPER_USER_SESSION_ACTIVE);
            addCustomValue("ActiveSuperUser", //$NON-NLS-1$
                    String.format("%s@%s", activeSuperUser.getLoginName(), activeSuperUser.getDomain()));
            log.warn("단일 관리자 접속 제한; 거부='{}@{}'; 사용중='{}@{}'",
                    user.getLoginName(), user.getDomain(),
                    activeSuperUser.getLoginName(), activeSuperUser.getDomain());
            setSucceeded(false);
            return;
        }
        sessionDataContainer.setSourceIp(engineSessionId, getParameters().getSourceIp());
        sessionDataContainer.setUser(engineSessionId, user);
        sessionDataContainer.refresh(engineSessionId);
        sessionDataContainer.setProfile(engineSessionId, profile);
        sessionDataContainer.setPrincipalName(engineSessionId, getParameters().getPrincipalName());
        sessionDataContainer.setSsoAccessToken(engineSessionId, getParameters().getSsoToken());
        sessionDataContainer.setSsoOvirtAppApiScope(engineSessionId, getParameters().getAppScope());
        getReturnValue().setActionReturnValue(engineSessionId);
        setSucceeded(true);
        sessionId = engineSessionId;
        if (unregisteredSuperUser) {
            recordUnregisteredSuperUserLogin(user);
        }
    }

    /**
     * The super user got in only through the lock-out safeguard: it has no dedicated address yet.
     * The login itself is recorded as usual; this records that the address check was waived.
     */
    private void recordUnregisteredSuperUserLogin(DbUser user) {
        AuditLogable event = new AuditLogableImpl();
        event.setUserId(user.getId());
        event.setUserName(getUserName());
        event.addCustomValue("SourceIP", StringUtils.isEmpty(sourceIp) ? UNKNOWN : sourceIp); //$NON-NLS-1$
        auditLog(event, AuditLogType.USER_LOGIN_WITHOUT_DEDICATED_IP_ALLOWED);
    }

    /**
     * Whether an internal user's login must be refused because it did not come from the one address
     * registered for that user.
     *
     * <p>Only internal (local) users are restricted. A user with a dedicated address may log in only
     * from it; a non-admin internal user with none registered is refused. A super user with none
     * registered is let through, so the restriction cannot lock every administrator out before
     * addresses have been assigned - once a super user is given a dedicated address, it is enforced
     * like any other.</p>
     */
    private boolean isLoginIpDenied(DbUser user, AuthenticationProfile profile, boolean isSuperUser) {
        boolean internal = INTERNAL_AUTHZ.equals(profile.getAuthzName());
        UserProfileProperty property = internal
                ? userProfileDao.getByName(SetUserDedicatedIpCommand.DEDICATED_LOGIN_IP_PROPERTY, user.getId())
                : null;
        dedicatedIp = property == null ? null : StringUtils.trimToNull(dedicatedIpFromContent(property.getContent()));
        boolean denied = isLoginDenied(internal, isSuperUser, dedicatedIp, sourceIp);
        if (denied) {
            loginDeniedReason = deniedReason(dedicatedIp);
            log.warn("로그인 거부(전용 접속 IP); 사용자='{}@{}'; 출발지='{}'; 전용 접속 IP='{}'; 사유='{}'",
                    user.getLoginName(), user.getDomain(), sourceIp,
                    dedicatedIp == null ? NO_DEDICATED_IP : dedicatedIp, loginDeniedReason);
        } else if (isUnregisteredSuperUserLogin(internal, isSuperUser, dedicatedIp)) {
            unregisteredSuperUser = true;
            log.warn("전용 접속 IP 미등록 수퍼유저 로그인 허용(관리자 잠금 방지); 사용자='{}@{}'; 출발지='{}'",
                    user.getLoginName(), user.getDomain(), sourceIp);
        }
        return denied;
    }

    /**
     * Whether the login must be refused because the request did not carry the terminal serial this
     * user logs in with: config.json's serialNum for an administrator, the serial registered for the
     * user (SetUserClientSerialCommand) for an internal user who is not one.
     *
     * <p>The checks before the login accept any registered serial, since who is logging in is not
     * known there; this is where a serial is bound to its user. The serial is never logged.</p>
     */
    private boolean isClientSerialDenied(DbUser user, AuthenticationProfile profile, boolean isAdmin) {
        boolean internal = INTERNAL_AUTHZ.equals(profile.getAuthzName());
        // No request at all is the engine logging itself in (the application server's console);
        // the engine host carries no serial, as the checks before the login also allow.
        boolean fromThisHost = StringUtils.isEmpty(sourceIp) || ClientSerialCheck.isThisHost(sourceIp);
        String registeredDigest = null;
        if (internal && !isAdmin && !fromThisHost) {
            UserProfileProperty property = userProfileDao.getByName(UserClientSerials.PROPERTY, user.getId());
            registeredDigest = property == null ? null : UserClientSerials.digestFromContent(property.getContent());
        }
        Refusal refusal = clientSerialRefusal(internal, isAdmin, fromThisHost, getParameters().getClientSerial(),
                isAdmin && !fromThisHost ? ClientSerialCheck.loadExpected() : null, registeredDigest);
        if (refusal != null) {
            serialDeniedReason = serialDeniedReason(isAdmin, refusal);
            log.warn("로그인 거부(단말기 시리얼); 사용자='{}@{}'; 출발지='{}'; 사유='{}'",
                    user.getLoginName(), user.getDomain(), sourceIp, serialDeniedReason);
        }
        return refusal != null;
    }

    /** The serial decision, given the raw inputs; null when the login may go on. */
    static Refusal clientSerialRefusal(boolean internalUser, boolean isAdmin, boolean fromThisHost,
            String presented, String adminSerial, String registeredUserDigest) {
        if (fromThisHost) {
            return null;
        }
        if (isAdmin) {
            return ClientSerialCheck.check(presented, adminSerial);
        }
        if (!internalUser) {
            // Nothing is registered for a directory user: the checks before the login stand.
            return null;
        }
        return ClientSerialCheck.checkUserSerial(presented, registeredUserDigest);
    }

    static String serialDeniedReason(boolean isAdmin, Refusal refusal) {
        switch (refusal) {
        case MISSING:
            return "단말기 시리얼 없음"; //$NON-NLS-1$
        case UNVERIFIABLE:
            return isAdmin ? "관리자 시리얼 확인 불가" : "사용자 시리얼 미등록"; //$NON-NLS-1$ //$NON-NLS-2$
        default:
            return isAdmin ? "관리자 시리얼 불일치" : "사용자 시리얼 불일치"; //$NON-NLS-1$ //$NON-NLS-2$
        }
    }

    /** Why a login refused by {@link #isLoginDenied} was refused, as the audit event states it. */
    static String deniedReason(String dedicatedIp) {
        return StringUtils.trimToNull(dedicatedIp) == null
                ? REASON_DEDICATED_IP_NOT_REGISTERED
                : REASON_DEDICATED_IP_MISMATCH;
    }

    /** Whether a login is let through only by the super-user lock-out safeguard. */
    static boolean isUnregisteredSuperUserLogin(boolean internalUser, boolean isSuperUser, String dedicatedIp) {
        return internalUser && isSuperUser && StringUtils.trimToNull(dedicatedIp) == null;
    }

    /**
     * The dedicated-login-IP decision, given the raw inputs.
     *
     * <p>Only internal users are restricted. A registered address must equal the source address; a
     * non-admin internal user with none registered is refused; a super user with none registered is
     * let through so the restriction cannot lock every administrator out before addresses are
     * assigned.</p>
     *
     * @return true when the login must be refused
     */
    static boolean isLoginDenied(boolean internalUser, boolean isSuperUser, String dedicatedIp, String sourceIp) {
        if (!internalUser) {
            return false;
        }
        String ip = StringUtils.trimToNull(dedicatedIp);
        if (ip == null) {
            return !isSuperUser;
        }
        return !ip.equals(StringUtils.trimToEmpty(sourceIp));
    }

    /**
     * The IP out of the stored property content. The dedicated IP is kept as a JSON string in the
     * jsonb property column (e.g. {@code "192.168.0.5"}); this reads it back to a plain address,
     * tolerating a value that was somehow stored unquoted.
     */
    public static String dedicatedIpFromContent(String content) {
        if (StringUtils.isEmpty(content)) {
            return null;
        }
        try {
            return SerializationFactory.getDeserializer().deserialize(content, String.class);
        } catch (RuntimeException exception) {
            String trimmed = content.trim();
            if (trimmed.length() >= 2 && trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
                trimmed = trimmed.substring(1, trimmed.length() - 1);
            }
            return StringUtils.trimToNull(trimmed);
        }
    }

    static int resolveSessionLimit(UserProfileProperty property, int defaultLimit) {
        if (property == null) {
            return defaultLimit;
        }
        try {
            int limit = Integer.parseInt(property.getContent());
            return limit > 0 ? limit : defaultLimit;
        } catch (NumberFormatException exception) {
            return defaultLimit;
        }
    }

    private static void flatGroups(Collection<ExtMap> groupIds, Map<String, ExtMap> accumulator) {
        for (ExtMap group : groupIds) {
            if (!accumulator.containsKey(group.<String>get(Authz.GroupRecord.ID))) {
                accumulator.put(group.get(Authz.GroupRecord.ID), group);
                flatGroups(group, Authz.GroupRecord.GROUPS, accumulator);
            }
        }
    }

    private static void flatGroups(ExtMap entity, ExtKey key, Map<String, ExtMap> accumulator) {
        for (ExtMap group : entity.<Collection<ExtMap>>get(key, Collections.<ExtMap>emptyList())) {
            if (!accumulator.containsKey(group.<String>get(Authz.GroupRecord.ID))) {
                accumulator.put(group.get(Authz.GroupRecord.ID), group);
                flatGroups(group, Authz.GroupRecord.GROUPS, accumulator);
            }
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

    @Override
    public AuditLogType getAuditLogTypeValue() {
        addCustomValue("SessionID", StringUtils.isEmpty(sessionId) ? UNKNOWN : sessionId);
        addCustomValue("SourceIP", StringUtils.isEmpty(sourceIp) ? UNKNOWN : sourceIp);
        addCustomValue("LoginErrMsg", "");
        AuditLogType type = auditLogTypeFor(getSucceeded(), getActionReturnValue());
        if (type == AuditLogType.USER_LOGIN_SERIAL_DENIED) {
            addCustomValue("LoginErrMsg", serialDeniedReason == null ? "" : serialDeniedReason);
        }
        if (type == AuditLogType.USER_LOGIN_IP_DENIED) {
            addCustomValue("LoginErrMsg", loginDeniedReason == null ? "" : loginDeniedReason);
            addCustomValue("DedicatedIp", dedicatedIp == null ? NO_DEDICATED_IP : dedicatedIp); //$NON-NLS-1$
        }
        return type;
    }

    /** The event a login ends with, given how it ended. */
    static AuditLogType auditLogTypeFor(boolean succeeded, Object error) {
        if (succeeded) {
            return AuditLogType.USER_VDC_LOGIN;
        }
        if (error == CreateUserSessionsError.NUM_OF_SESSIONS_EXCEEDED) {
            return AuditLogType.USER_MAX_SESSIONS_EXCEEDED;
        }
        if (error == CreateUserSessionsError.SUPER_USER_SESSION_ACTIVE) {
            return AuditLogType.SUPER_USER_SESSION_ALREADY_ACTIVE;
        }
        if (error == CreateUserSessionsError.LOGIN_IP_NOT_ALLOWED) {
            return AuditLogType.USER_LOGIN_IP_DENIED;
        }
        if (error == CreateUserSessionsError.CLIENT_SERIAL_NOT_ALLOWED) {
            return AuditLogType.USER_LOGIN_SERIAL_DENIED;
        }
        return AuditLogType.USER_VDC_LOGIN_FAILED;
    }
}
