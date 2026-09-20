package org.ovirt.engine.core.dao;

import java.util.List;

import javax.inject.Named;
import javax.inject.Singleton;

import org.ovirt.engine.core.common.businessentities.VmGuestEventMark;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dal.dbbroker.DbFacadeUtils;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

/**
 * {@code VmGuestEventMarkDaoImpl} provides a concrete implementation of {@link VmGuestEventMarkDao}.
 */
@Named
@Singleton
public class VmGuestEventMarkDaoImpl extends BaseDao implements VmGuestEventMarkDao {

    private static final RowMapper<VmGuestEventMark> markRowMapper = (rs, rowNum) -> {
        VmGuestEventMark entity = new VmGuestEventMark();
        entity.setVmId(getGuidDefaultEmpty(rs, "vm_id"));
        entity.setLogName(rs.getString("log_name"));
        entity.setLastRecordId(rs.getLong("last_record_id"));
        entity.setUpdateDate(DbFacadeUtils.fromDate(rs.getTimestamp("update_date")));
        return entity;
    };

    @Override
    public List<VmGuestEventMark> getByVmId(Guid vmId) {
        return getCallsHandler().executeReadList("GetVmGuestEventMarksByVmId",
                markRowMapper,
                getCustomMapSqlParameterSource().addValue("vm_id", vmId));
    }

    @Override
    public void save(VmGuestEventMark mark) {
        MapSqlParameterSource parameterSource = getCustomMapSqlParameterSource()
                .addValue("vm_id", mark.getVmId())
                .addValue("log_name", mark.getLogName())
                .addValue("last_record_id", mark.getLastRecordId());

        getCallsHandler().executeModification("UpsertVmGuestEventMark", parameterSource);
    }
}
