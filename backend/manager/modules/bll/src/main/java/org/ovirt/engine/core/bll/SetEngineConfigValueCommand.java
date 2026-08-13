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
import org.ovirt.engine.core.common.config.Config;
import org.ovirt.engine.core.common.config.ConfigCommon;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.VdcOptionDao;

public class SetEngineConfigValueCommand<T extends EngineConfigValueParameters> extends CommandBase<T> {

    @Inject
    private VdcOptionDao vdcOptionDao;

    public SetEngineConfigValueCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected boolean validate() {
        return getParameters().getKey() != null
                && !getParameters().getKey().trim().isEmpty()
                && getParameters().getValue() != null;
    }

    @Override
    protected void executeCommand() {
        try {
            String key = getParameters().getKey().trim();
            ConfigValues.valueOf(key);
            VdcOption option = vdcOptionDao.getByNameAndVersion(key, ConfigCommon.defaultConfigurationVersion);
            if (option == null) {
                fail("설정 값을 찾을 수 없습니다: " + key); //$NON-NLS-1$
                return;
            }

            option.setOptionValue(getParameters().getValue());
            vdcOptionDao.update(option);
            Config.refresh();
            getReturnValue().setActionReturnValue("수정 완료: " + key); //$NON-NLS-1$
            setSucceeded(true);
        } catch (IllegalArgumentException e) {
            fail("존재하지 않는 설정 변수입니다."); //$NON-NLS-1$
        } catch (RuntimeException e) {
            log.error("Failed to set engine-config value", e); //$NON-NLS-1$
            fail(e.getMessage());
        }
    }

    private void fail(String message) {
        String failureMessage = message == null ? "설정 수정에 실패했습니다." : message; //$NON-NLS-1$
        getReturnValue().setActionReturnValue(failureMessage);
        getReturnValue().getExecuteFailedMessages().add(failureMessage);
        setSucceeded(false);
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(Guid.SYSTEM, VdcObjectType.System,
                ActionGroup.CONFIGURE_ENGINE));
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return AuditLogType.UNASSIGNED;
    }
}
