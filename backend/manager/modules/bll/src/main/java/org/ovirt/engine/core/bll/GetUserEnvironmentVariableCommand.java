package org.ovirt.engine.core.bll;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.common.action.EngineConfigValueParameters;

public class GetUserEnvironmentVariableCommand<T extends EngineConfigValueParameters>
        extends UserEnvironmentVariableCommandBase<T> {

    public GetUserEnvironmentVariableCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected boolean validate() {
        return hasSupportedKey();
    }

    @Override
    protected void executeCommand() {
        executeTool("ovirt-aaa-jdbc-tool", "settings", "show", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                "--name=" + getParameters().getKey().trim()); //$NON-NLS-1$
    }
}
