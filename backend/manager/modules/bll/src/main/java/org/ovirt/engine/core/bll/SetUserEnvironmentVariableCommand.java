package org.ovirt.engine.core.bll;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.common.action.EngineConfigValueParameters;

public class SetUserEnvironmentVariableCommand<T extends EngineConfigValueParameters>
        extends UserEnvironmentVariableCommandBase<T> {

    public SetUserEnvironmentVariableCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected boolean validate() {
        return hasSupportedKey()
                && getParameters().getValue() != null
                && getParameters().getValue().matches("[0-9]+"); //$NON-NLS-1$
    }

    @Override
    protected void executeCommand() {
        executeTool("ovirt-aaa-jdbc-tool", "settings", "set", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                "--name=" + getParameters().getKey().trim(), //$NON-NLS-1$
                "--value=" + getParameters().getValue()); //$NON-NLS-1$
    }
}
