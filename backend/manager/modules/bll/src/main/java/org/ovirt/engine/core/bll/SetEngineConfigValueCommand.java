package org.ovirt.engine.core.bll;

import java.util.Collections;
import java.util.List;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.EngineConfigValueParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.common.businessentities.VdcOption;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dal.dbbroker.generic.DBConfigUtils;
import org.ovirt.engine.core.dao.VdcOptionDao;

public class SetEngineConfigValueCommand<T extends EngineConfigValueParameters> extends CommandBase<T> {

    @Inject
    private VdcOptionDao vdcOptionDao;

    @Inject
    private DBConfigUtils dbConfigUtils;

    public SetEngineConfigValueCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected boolean validate() {
        addCustomValue("ConfigKey", getParameters().getKey() == null ? "" : getParameters().getKey().trim()); //$NON-NLS-1$ //$NON-NLS-2$
        return getParameters().getKey() != null
                && !getParameters().getKey().trim().isEmpty()
                && getParameters().getValue() != null;
    }

    @Override
    protected void executeCommand() {
        try {
            String key = getParameters().getKey().trim();
            VdcOption option = vdcOptionDao.getByNameAndVersion(key, "general"); //$NON-NLS-1$
            if (option == null) {
                String message = "존재하지 않는 변수입니다. 다시확인하세요"; //$NON-NLS-1$
                getReturnValue().setActionReturnValue(message);
                getReturnValue().getExecuteFailedMessages().add(message);
                setSucceeded(false);
                return;
            }

            option.setOptionValue(getParameters().getValue());
            vdcOptionDao.update(option);
            dbConfigUtils.refresh();
            getReturnValue().setActionReturnValue("수정 완료: " + key); //$NON-NLS-1$
            setSucceeded(true);
        } catch (Exception e) {
            log.error("Failed to set engine-config value", e); //$NON-NLS-1$
            getReturnValue().getExecuteFailedMessages().add(e.getMessage());
            setSucceeded(false);
        }
    }


    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(Guid.SYSTEM, VdcObjectType.System,
                ActionGroup.CONFIGURE_ENGINE));
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return getSucceeded() ? AuditLogType.ENGINE_ENVIRONMENT_VARIABLE_UPDATED
                : AuditLogType.ENGINE_ENVIRONMENT_VARIABLE_UPDATE_FAILED;
    }
}
