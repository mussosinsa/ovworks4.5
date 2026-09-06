package org.ovirt.engine.ui.webadmin.section.main.presenter.popup;

import java.util.ArrayList;
import java.util.List;

import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.ExecuteVmGuestCommandParameters;
import org.ovirt.engine.core.common.businessentities.network.VmNetworkInterface;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.ui.common.presenter.AbstractPopupPresenterWidget;
import org.ovirt.engine.ui.frontend.AsyncQuery;
import org.ovirt.engine.ui.frontend.Frontend;
import org.ovirt.engine.ui.uicommonweb.dataprovider.AsyncDataProvider;
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
        com.google.gwt.event.dom.client.HasClickHandlers getApplyNetworkSettingsButton();
        com.google.gwt.event.dom.client.HasClickHandlers getRefreshNetworkAdaptersButton();
        void clearNetworkAdapters();
        void addNetworkAdapter(String label, String macAddress);
        String getSelectedMacAddress();
        com.google.gwt.event.dom.client.HasClickHandlers getRefreshGuestEventsButton();
        void setGuestEvents(List<String[]> events);
        void setGuestEventsMessage(String message);
        com.google.gwt.event.dom.client.HasClickHandlers getApplyFileSharingSettingsButton();
        String getVmId();
        String getGuestCommandPath();
        boolean isAppLockerEnabled();
        void setGuestCommandResult(String result);
        void setVmId(String vmId);
        boolean isNetworkEnabled();
        String getIpAddress();
        String getSubnetMask();
        String getGateway();
        void setNetworkSettingsResult(String result);
        boolean isFileSharingBlocked();
        void setFileSharingSettingsResult(String result);
    }

    @Inject
    public VmSecurityControlPopupPresenterWidget(EventBus eventBus, ViewDef view) {
        super(eventBus, view);
        registerHandler(view.getExecuteGuestCommandButton().addClickHandler(event -> executeGuestCommand()));
        registerHandler(view.getApplyNetworkSettingsButton().addClickHandler(event -> applyNetworkSettings()));
        registerHandler(view.getRefreshNetworkAdaptersButton().addClickHandler(event -> loadNetworkAdapters()));
        registerHandler(view.getRefreshGuestEventsButton().addClickHandler(event -> loadGuestEvents()));
        registerHandler(view.getApplyFileSharingSettingsButton().addClickHandler(event -> applyFileSharingSettings()));
    }

    private void applyFileSharingSettings() {
        final Guid vmId;
        try {
            vmId = Guid.createGuidFromString(getView().getVmId().trim());
        } catch (Exception e) {
            getView().setFileSharingSettingsResult(constants.vmSecurityInvalidVmUuid());
            return;
        }
        ExecuteVmGuestCommandParameters parameters = new ExecuteVmGuestCommandParameters();
        parameters.setVmId(vmId);
        parameters.setFileSharingBlocked(getView().isFileSharingBlocked());
        getView().setFileSharingSettingsResult(constants.vmSecurityExecutingCommand());
        Frontend.getInstance().runAction(ActionType.ExecuteVmGuestCommand, parameters, result -> {
            if (result != null && result.getReturnValue() != null) {
                Object value = result.getReturnValue().getActionReturnValue();
                getView().setFileSharingSettingsResult(value == null
                        ? result.getReturnValue().getExecuteFailedMessages().toString() : value.toString());
            }
        });
    }

    private void applyNetworkSettings() {
        final Guid vmId;
        try {
            vmId = Guid.createGuidFromString(getView().getVmId().trim());
        } catch (Exception e) {
            getView().setNetworkSettingsResult(constants.vmSecurityInvalidVmUuid());
            return;
        }
        String macAddress = getView().getSelectedMacAddress();
        if (macAddress == null || macAddress.isEmpty()) {
            getView().setNetworkSettingsResult(constants.vmSecurityAdapterRequired());
            return;
        }
        ExecuteVmGuestCommandParameters parameters = new ExecuteVmGuestCommandParameters();
        parameters.setVmId(vmId);
        parameters.setNetworkEnabled(getView().isNetworkEnabled());
        parameters.setMacAddress(macAddress);
        parameters.setIpAddress(getView().getIpAddress());
        parameters.setSubnetMask(getView().getSubnetMask());
        parameters.setGateway(getView().getGateway());
        getView().setNetworkSettingsResult(constants.vmSecurityExecutingCommand());
        Frontend.getInstance().runAction(ActionType.ExecuteVmGuestCommand, parameters, result -> {
            if (result != null && result.getReturnValue() != null) {
                Object value = result.getReturnValue().getActionReturnValue();
                getView().setNetworkSettingsResult(value == null
                        ? result.getReturnValue().getExecuteFailedMessages().toString() : value.toString());
            }
        });
    }

    private void executeGuestCommand() {
        String allowedPath = getView().getGuestCommandPath().trim();
        if (getView().isAppLockerEnabled() && allowedPath.isEmpty()) {
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
        ExecuteVmGuestCommandParameters parameters = new ExecuteVmGuestCommandParameters();
        parameters.setVmId(vmId);
        parameters.setAppLockerEnabled(getView().isAppLockerEnabled());
        parameters.setAllowedAppPath(allowedPath);
        Frontend.getInstance().runAction(ActionType.ExecuteVmGuestCommand,
                parameters, result -> {
                    if (result != null && result.getReturnValue() != null) {
                        Object value = result.getReturnValue().getActionReturnValue();
                        getView().setGuestCommandResult(value == null
                                ? result.getReturnValue().getExecuteFailedMessages().toString() : value.toString());
                    }
                });
    }

    public void setVmId(Guid vmId) {
        getView().setVmId(vmId == null ? "" : vmId.toString()); //$NON-NLS-1$
        loadNetworkAdapters();
    }

    /** Pulls the recent entries of the guest event logs into the table. */
    private void loadGuestEvents() {
        final Guid vmId;
        try {
            vmId = Guid.createGuidFromString(getView().getVmId().trim());
        } catch (Exception e) {
            getView().setGuestEventsMessage(constants.vmSecurityInvalidVmUuid());
            return;
        }
        getView().setGuestEventsMessage(constants.vmSecurityLoadingEvents());
        ExecuteVmGuestCommandParameters parameters = new ExecuteVmGuestCommandParameters();
        parameters.setVmId(vmId);
        parameters.setGuestEventsRequested(Boolean.TRUE);
        Frontend.getInstance().runAction(ActionType.ExecuteVmGuestCommand, parameters, result -> {
            if (result == null || result.getReturnValue() == null) {
                return;
            }
            Object value = result.getReturnValue().getActionReturnValue();
            if (!result.getReturnValue().getSucceeded() || value == null) {
                getView().setGuestEventsMessage(value == null
                        ? result.getReturnValue().getExecuteFailedMessages().toString() : value.toString());
                return;
            }
            getView().setGuestEventsMessage(""); //$NON-NLS-1$
            getView().setGuestEvents(parseGuestEvents(value.toString()));
        });
    }

    /** One event per line, its fields separated by the character the command agreed on. */
    static List<String[]> parseGuestEvents(String output) {
        List<String[]> events = new ArrayList<>();
        for (String line : output.split("\n")) { //$NON-NLS-1$
            // Only the line ending is stripped: trimming would drop the separator of an empty
            // trailing field, and with it the column it belongs to.
            String event = line.replace("\r", ""); //$NON-NLS-1$ //$NON-NLS-2$
            if (!event.trim().isEmpty()) {
                events.add(event.split(ExecuteVmGuestCommandParameters.GUEST_EVENT_SEPARATOR, -1));
            }
        }
        return events;
    }

    /** Fills the adapter list with the interfaces the VM actually has. */
    private void loadNetworkAdapters() {
        getView().clearNetworkAdapters();
        final Guid vmId;
        try {
            vmId = Guid.createGuidFromString(getView().getVmId().trim());
        } catch (Exception e) {
            return;
        }
        AsyncDataProvider.getInstance().getVmNicList(
                new AsyncQuery<List<VmNetworkInterface>>(nics -> {
                    getView().clearNetworkAdapters();
                    if (nics == null) {
                        return;
                    }
                    for (VmNetworkInterface nic : nics) {
                        if (nic.getMacAddress() != null && !nic.getMacAddress().isEmpty()) {
                            getView().addNetworkAdapter(
                                    nic.getName() + " (" + nic.getMacAddress() + ")", nic.getMacAddress()); //$NON-NLS-1$ //$NON-NLS-2$
                        }
                    }
                }), vmId);
    }
}
