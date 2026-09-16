package org.ovirt.engine.core.dao;

import java.util.Date;
import java.util.List;

import javax.inject.Named;
import javax.inject.Singleton;

import org.springframework.jdbc.core.RowMapper;

/**
 * {@code UserLoginFailuresDaoImpl} provides a concrete implementation of
 * {@link UserLoginFailuresDao}.
 */
@Named
@Singleton
public class UserLoginFailuresDaoImpl extends BaseDao implements UserLoginFailuresDao {

    private static final RowMapper<String> releasedPrincipalRowMapper =
            (rs, rowNum) -> rs.getString("released_principal");

    @Override
    public void clearByLoginName(String loginName) {
        getCallsHandler().executeModification("ClearUserLoginFailuresByLoginName",
                getCustomMapSqlParameterSource().addValue("login_name", loginName));
    }

    @Override
    public List<String> releaseExpired(Date now) {
        return getCallsHandler().executeReadList("ReleaseExpiredUserLoginFailures",
                releasedPrincipalRowMapper,
                getCustomMapSqlParameterSource().addValue("now", now));
    }
}
