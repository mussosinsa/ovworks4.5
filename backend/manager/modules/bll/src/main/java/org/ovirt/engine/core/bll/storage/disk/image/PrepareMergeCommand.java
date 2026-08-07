package org.ovirt.engine.core.bll.storage.disk.image;

import org.ovirt.engine.core.bll.InternalCommandAttribute;
import org.ovirt.engine.core.bll.NonTransactiveCommandAttribute;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.common.action.ColdMergeCommandParameters;
import org.ovirt.engine.core.common.asynctasks.AsyncTaskType;
import org.ovirt.engine.core.common.vdscommands.VDSCommandType;

@NonTransactiveCommandAttribute
@InternalCommandAttribute
public class PrepareMergeCommand<T extends ColdMergeCommandParameters> extends MergeSPMBaseCommand<T> {

    public PrepareMergeCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected void executeCommand() {
        executeSPMMergeCommand(VDSCommandType.PrepareMerge);
    }

    @Override
    protected AsyncTaskType getTaskType() {
        return AsyncTaskType.prepareMerge;
    }
}
