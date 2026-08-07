package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.SetEngineSessionLimitParameters;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.utils.EngineLocalConfig;

public class SetEngineSessionLimitCommand extends CommandBase<SetEngineSessionLimitParameters> {

    private static final String SESSION_LIMIT_CONF = "99-limit-user-sessions.conf"; //$NON-NLS-1$
    private static final String SESSION_LIMIT_KEY = "ENGINE_MAX_USER_SESSIONS"; //$NON-NLS-1$

    public SetEngineSessionLimitCommand(SetEngineSessionLimitParameters parameters, CommandContext commandContext) {
        super(parameters, commandContext);
    }

    @Override
    protected boolean validate() {
        return getParameters().getSessionLimit() > 0;
    }

    @Override
    protected void executeCommand() {
        int sessionLimit = getParameters().getSessionLimit();
        Path confDir = EngineLocalConfig.getInstance().getEtcDir().toPath().resolve("engine.conf.d"); //$NON-NLS-1$
        Path confFile = confDir.resolve(SESSION_LIMIT_CONF);
        try {
            Files.createDirectories(confDir);
            String contents = SESSION_LIMIT_KEY + "=" + sessionLimit + System.lineSeparator();
            Files.write(confFile, contents.getBytes(StandardCharsets.UTF_8));
            EngineLocalConfig.clearInstance();
            setSucceeded(true);
        } catch (IOException exception) {
            log.error("Failed to update session limit configuration at {}", confFile, exception);
            setSucceeded(false);
        }
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(Guid.SYSTEM,
                VdcObjectType.System,
                ActionGroup.CONFIGURE_ENGINE));
    }
}
