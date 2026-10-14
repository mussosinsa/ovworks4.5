package org.ovirt.engine.core.bll.aaa;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.bll.QueriesCommandBase;
import org.ovirt.engine.core.bll.SetUserDedicatedIpCommand;
import org.ovirt.engine.core.bll.context.EngineContext;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.common.queries.NameQueryParameters;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogableImpl;
import org.ovirt.engine.core.dao.DbUserDao;
import org.ovirt.engine.core.dao.RoleDao;
import org.ovirt.engine.core.dao.UserProfileDao;

/**
 * Whether the web portal - the welcome page, the administration portal and the login pages - is
 * to be refused to the address named in the parameters, recording the refusal when it is.
 *
 * <p>A user's dedicated login address is put on the web server's terminal list so that the user can
 * log in from it, which is done with the client program over the REST API. Being on that list let
 * the address reach the web portal as well, which the dedicated address was never given for. So
 * the portal is refused to an address that is the dedicated address of users none of whom is an
 * administrator. An administrator's dedicated address keeps the portal: refusing it would lock the
 * administrator out of the one place the addresses are managed from.</p>
 *
 * <p>An administrator is a user with an administrator role given to the user directly, the way the
 * built-in administrator and the accounts made from the user screen have it. A role that reaches a
 * user only through a directory group is not seen here, because the engine learns a user's groups
 * only at login.</p>
 */
public class IsWebPortalDeniedForAddressQuery<P extends NameQueryParameters> extends QueriesCommandBase<P> {

    @Inject
    private UserProfileDao userProfileDao;
    @Inject
    private DbUserDao dbUserDao;
    @Inject
    private RoleDao roleDao;
    @Inject
    private AuditLogDirector auditLogDirector;

    public IsWebPortalDeniedForAddressQuery(P parameters, EngineContext engineContext) {
        super(parameters, engineContext);
    }

    @Override
    protected void executeQueryCommand() {
        String address = StringUtils.trimToNull(getParameters().getName());
        List<Guid> users = address == null ? List.of()
                : usersWithDedicatedIp(userProfileDao.getAllByName(
                        SetUserDedicatedIpCommand.DEDICATED_LOGIN_IP_PROPERTY), address);
        boolean denied = isDenied(users, this::isAdministrator);
        if (denied) {
            record(address, users);
        }
        getQueryReturnValue().setReturnValue(denied);
    }

    /** @return the users whose dedicated login address is this one */
    static List<Guid> usersWithDedicatedIp(List<UserProfileProperty> properties, String address) {
        List<Guid> users = new ArrayList<>();
        for (UserProfileProperty property : properties) {
            if (address.equals(CreateUserSessionCommand.dedicatedIpFromContent(property.getContent()))) {
                users.add(property.getUserId());
            }
        }
        return users;
    }

    /** Refused when the address is somebody's dedicated address and nobody's who administers. */
    static boolean isDenied(List<Guid> users, Predicate<Guid> isAdministrator) {
        return !users.isEmpty() && users.stream().noneMatch(isAdministrator);
    }

    private boolean isAdministrator(Guid userId) {
        return !roleDao.getAnyAdminRoleForUserAndGroups(userId, "").isEmpty(); //$NON-NLS-1$
    }

    private void record(String address, List<Guid> users) {
        List<String> names = new ArrayList<>();
        for (Guid userId : users) {
            DbUser user = dbUserDao.get(userId);
            names.add(user == null ? userId.toString() : user.getLoginName());
        }
        log.warn("웹 포털 접속 차단(사용자 전용 접속 IP); 출발지='{}'; 전용 IP 사용자='{}'", address, names);
        AuditLogable event = new AuditLogableImpl();
        // One record a minute for each address, not one for every page a browser asks for.
        event.setCustomId(address);
        event.addCustomValue("SourceIP", address); //$NON-NLS-1$
        event.addCustomValue("DedicatedIpUsers", String.join(", ", names)); //$NON-NLS-1$ //$NON-NLS-2$
        auditLogDirector.log(event, AuditLogType.WEB_PORTAL_DENIED_FOR_DEDICATED_IP);
    }
}
