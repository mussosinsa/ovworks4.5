package org.ovirt.engine.core.dao;

import java.util.Date;
import java.util.List;

import javax.inject.Named;
import javax.inject.Singleton;

import org.ovirt.engine.core.common.businessentities.aaa.UserPasswordHistoryEntry;
import org.ovirt.engine.core.dal.dbbroker.DbFacadeUtils;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

/**
 * {@code UserPasswordHistoryDaoImpl} provides a concrete implementation of
 * {@link UserPasswordHistoryDao}.
 */
@Named
@Singleton
public class UserPasswordHistoryDaoImpl extends BaseDao implements UserPasswordHistoryDao {

    private static final RowMapper<UserPasswordHistoryEntry> entryRowMapper = (rs, rowNum) -> {
        UserPasswordHistoryEntry entity = new UserPasswordHistoryEntry();
        entity.setId(rs.getLong("id"));
        entity.setPrincipal(rs.getString("principal"));
        entity.setPasswordHash(rs.getString("password_hash"));
        entity.setChangeDate(DbFacadeUtils.fromDate(rs.getTimestamp("change_date")));
        return entity;
    };

    @Override
    public List<UserPasswordHistoryEntry> getByPrincipal(String principal, int limit) {
        return getCallsHandler().executeReadList("GetUserPasswordHistoryByPrincipal",
                entryRowMapper,
                getCustomMapSqlParameterSource()
                        .addValue("principal", principal)
                        .addValue("limit", limit));
    }

    @Override
    public void save(UserPasswordHistoryEntry entry) {
        MapSqlParameterSource parameterSource = getCustomMapSqlParameterSource()
                .addValue("principal", entry.getPrincipal())
                .addValue("password_hash", entry.getPasswordHash())
                .addValue("change_date", entry.getChangeDate());

        getCallsHandler().executeModification("InsertUserPasswordHistory", parameterSource);
    }

    @Override
    public void cleanup(String principal, Date threshold, int keep) {
        MapSqlParameterSource parameterSource = getCustomMapSqlParameterSource()
                .addValue("principal", principal)
                .addValue("threshold", threshold)
                .addValue("keep", keep);

        getCallsHandler().executeModification("CleanupUserPasswordHistory", parameterSource);
    }
}
