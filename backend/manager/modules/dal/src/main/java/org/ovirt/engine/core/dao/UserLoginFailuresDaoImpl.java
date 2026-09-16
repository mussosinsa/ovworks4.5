package org.ovirt.engine.core.dao;

import javax.inject.Named;
import javax.inject.Singleton;

/**
 * {@code UserLoginFailuresDaoImpl} provides a concrete implementation of
 * {@link UserLoginFailuresDao}.
 */
@Named
@Singleton
public class UserLoginFailuresDaoImpl extends BaseDao implements UserLoginFailuresDao {

    @Override
    public void clearByLoginName(String loginName) {
        getCallsHandler().executeModification("ClearUserLoginFailuresByLoginName",
                getCustomMapSqlParameterSource().addValue("login_name", loginName));
    }
}
