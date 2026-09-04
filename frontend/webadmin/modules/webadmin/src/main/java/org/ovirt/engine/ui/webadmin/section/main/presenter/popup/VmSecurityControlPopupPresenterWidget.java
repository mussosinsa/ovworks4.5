package org.ovirt.engine.ui.webadmin.section.main.presenter.popup;

import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.ExecuteVmGuestCommandParameters;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.ui.common.presenter.AbstractPopupPresenterWidget;
import org.ovirt.engine.ui.frontend.Frontend;
import org.ovirt.engine.ui.webadmin.ApplicationConstants;
import org.ovirt.engine.ui.webadmin.gin.AssetProvider;

import com.google.gwt.event.shared.EventBus;
import com.google.inject.Inject;

/**
 * Implements the Security Settings popup dialog.
 */
public class VmSecurityControlPopupPresenterWidget extends AbstractPopupPresenterWidget<VmSecurityControlPopupPresenterWidget.ViewDef> {

    private static final ApplicationConstants constants = AssetProvider.getConstants();

    public interface ViewDef extends AbstractPopupPresenterWidget.ViewDef {
        com.google.gwt.event.dom.client.HasClickHandlers getExecuteGuestCommandButton();
        com.google.gwt.event.dom.client.HasClickHandlers getApplyButton();
        String getVmId();
        String getGuestCommandPath();
        void setGuestCommandResult(String result);
        void setVmId(String vmId);
    }

    @Inject
    public VmSecurityControlPopupPresenterWidget(EventBus eventBus, ViewDef view) {
        super(eventBus, view);
        registerHandler(view.getExecuteGuestCommandButton().addClickHandler(event -> executeGuestCommand()));
        registerHandler(view.getApplyButton().addClickHandler(event -> onClose()));
    }

    private void executeGuestCommand() {
        String commandPath = getView().getGuestCommandPath().trim();
        if (commandPath.isEmpty()) {
            getView().setGuestCommandResult(constants.vmSecurityCommandRequired());
            return;
        }

        final Guid vmId;
        try {
            vmId = Guid.createGuidFromString(getView().getVmId().trim());
        } catch (Exception e) {
            getView().setGuestCommandResult(constants.vmSecurityInvalidVmUuid());
            return;
        }
        getView().setGuestCommandResult(constants.vmSecurityExecutingCommand());
        Frontend.getInstance().runAction(ActionType.ExecuteVmGuestCommand,
                new ExecuteVmGuestCommandParameters(vmId, commandPath), result -> {
                    if (result != null && result.getReturnValue() != null) {
                        Object value = result.getReturnValue().getActionReturnValue();
                        getView().setGuestCommandResult(value == null
                                ? result.getReturnValue().getExecuteFailedMessages().toString() : value.toString());
                    }
                });
    }

    public void setVmId(Guid vmId) {
        getView().setVmId(vmId == null ? "" : vmId.toString()); //$NON-NLS-1$
    }
}
