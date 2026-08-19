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
public class SecuritySettingsPopupPresenterWidget extends AbstractPopupPresenterWidget<SecuritySettingsPopupPresenterWidget.ViewDef> {

    private static final ApplicationConstants constants = AssetProvider.getConstants();

    public interface ViewDef extends AbstractPopupPresenterWidget.ViewDef {
        void setIntegrityCheckHandler(Runnable handler);
        void setClientManagementHandler(Runnable handler);
        com.google.gwt.event.dom.client.HasClickHandlers getExecuteGuestCommandButton();
        String getVmId();
        String getGuestCommandPath();
        void setGuestCommandResult(String result);
    }

    @Inject
    public SecuritySettingsPopupPresenterWidget(EventBus eventBus, ViewDef view) {
        super(eventBus, view);
        registerHandler(view.getExecuteGuestCommandButton().addClickHandler(event -> executeGuestCommand()));
    }

    private void executeGuestCommand() {
        final Guid vmId;
        try {
            vmId = Guid.createGuidFromString(getView().getVmId().trim());
        } catch (Exception e) {
            getView().setGuestCommandResult(constants.vmSecurityInvalidVmUuid());
            return;
        }
        getView().setGuestCommandResult(constants.vmSecurityExecutingCommand());
        Frontend.getInstance().runAction(ActionType.ExecuteVmGuestCommand,
                new ExecuteVmGuestCommandParameters(vmId, getView().getGuestCommandPath().trim()), result -> {
                    if (result != null && result.getReturnValue() != null) {
                        Object value = result.getReturnValue().getActionReturnValue();
                        getView().setGuestCommandResult(value == null
                                ? result.getReturnValue().getExecuteFailedMessages().toString() : value.toString());
                    }
                });
    }
}
