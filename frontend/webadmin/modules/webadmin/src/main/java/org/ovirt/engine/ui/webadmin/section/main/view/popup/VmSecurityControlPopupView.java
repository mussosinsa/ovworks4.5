package org.ovirt.engine.ui.webadmin.section.main.view.popup;

import java.util.ArrayList;
import java.util.List;

import org.ovirt.engine.ui.common.view.AbstractPopupView;
import org.ovirt.engine.ui.common.widget.dialog.PopupNativeKeyPressHandler;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogButton;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogPanel;
import org.ovirt.engine.ui.webadmin.ApplicationConstants;
import org.ovirt.engine.ui.webadmin.gin.AssetProvider;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.VmSecurityControlPopupPresenterWidget;

import com.google.gwt.core.client.GWT;
import com.google.gwt.event.dom.client.HasClickHandlers;
import com.google.gwt.event.shared.EventBus;
import com.google.gwt.event.shared.HandlerRegistration;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.user.client.ui.Button;
import com.google.gwt.user.client.ui.FlexTable;
import com.google.gwt.user.client.ui.HTMLPanel;
import com.google.gwt.user.client.ui.Label;
import com.google.gwt.user.client.ui.ListBox;
import com.google.gwt.user.client.ui.RadioButton;
import com.google.gwt.user.client.ui.TextArea;
import com.google.gwt.user.client.ui.TextBox;
import com.google.inject.Inject;

public class VmSecurityControlPopupView extends AbstractPopupView<SimpleDialogPanel>
        implements VmSecurityControlPopupPresenterWidget.ViewDef {

    interface ViewUiBinder extends UiBinder<SimpleDialogPanel, VmSecurityControlPopupView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    private static final ApplicationConstants constants = AssetProvider.getConstants();

    /** The events last fetched from the guest. The filter box narrows what is drawn from them. */
    private final List<String[]> guestEvents = new ArrayList<>();

    @UiField
    SimpleDialogButton closeButton;

    @UiField
    TextBox vmId;

    @UiField
    TextBox guestCommandPath;

    @UiField
    Button executeGuestCommandButton;

    @UiField
    TextArea guestCommandResult;

    @UiField
    RadioButton enableAppLockerRadioButton;

    @UiField
    ListBox networkAdapter;

    @UiField
    Button refreshNetworkAdaptersButton;

    @UiField
    RadioButton disableNetworkRadioButton;

    @UiField
    RadioButton enableNetworkRadioButton;

    @UiField
    HTMLPanel ipDetailsPanel;

    @UiField
    TextBox ipAddress;

    @UiField
    TextBox subnetMask;

    @UiField
    TextBox gateway;

    @UiField
    Button applyNetworkSettingsButton;

    @UiField
    Label networkSettingsResult;

    @UiField
    RadioButton blockFileSharingRadioButton;

    @UiField
    Button applyFileSharingSettingsButton;

    @UiField
    Label fileSharingSettingsResult;

    @UiField
    RadioButton blockManagementCommandsRadioButton;

    @UiField
    Button applyManagementBlockButton;

    @UiField
    Label managementBlockResult;

    @UiField
    TextBox eventFilter;

    @UiField
    Button refreshGuestEventsButton;

    @UiField
    FlexTable guestEventTable;

    @UiField
    Label guestEventsMessage;

    @Inject
    public VmSecurityControlPopupView(EventBus eventBus) {
        super(eventBus);
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        disableNetworkRadioButton.addValueChangeHandler(event -> {
            if (event.getValue()) {
                setNetworkEnabled(false);
            }
        });
        enableNetworkRadioButton.addValueChangeHandler(event -> {
            if (event.getValue()) {
                setNetworkEnabled(true);
            }
        });
        setNetworkEnabled(enableNetworkRadioButton.getValue());
        eventFilter.getElement().setAttribute("placeholder", constants.vmSecurityFilter()); //$NON-NLS-1$
        eventFilter.addKeyUpHandler(event -> drawGuestEvents());
        drawGuestEvents();
    }

    /** Redraws the table from the events held, keeping only the ones the filter matches. */
    private void drawGuestEvents() {
        guestEventTable.removeAllRows();
        guestEventTable.setText(0, 0, constants.vmSecurityTime());
        guestEventTable.setText(0, 1, constants.vmSecurityEventType());
        guestEventTable.setText(0, 2, constants.vmSecurityStatus());
        guestEventTable.setText(0, 3, constants.vmSecurityMessage());
        guestEventTable.getRowFormatter().setStyleName(0, "active"); //$NON-NLS-1$

        String filter = eventFilter.getText().trim().toLowerCase();
        int row = 1;
        for (String[] event : guestEvents) {
            if (!matches(event, filter)) {
                continue;
            }
            for (int column = 0; column < 4; column++) {
                // setText escapes, which matters because the guest writes these messages.
                guestEventTable.setText(row, column, column < event.length ? event[column] : ""); //$NON-NLS-1$
            }
            row++;
        }
        if (row == 1 && !guestEvents.isEmpty()) {
            guestEventsMessage.setText(constants.vmSecurityNoEvents());
        }
    }

    private static boolean matches(String[] event, String filter) {
        if (filter.isEmpty()) {
            return true;
        }
        for (String field : event) {
            if (field.toLowerCase().contains(filter)) {
                return true;
            }
        }
        return false;
    }

    private void setNetworkEnabled(boolean enabled) {
        disableNetworkRadioButton.setValue(!enabled, false);
        enableNetworkRadioButton.setValue(enabled, false);
        ipDetailsPanel.setVisible(enabled);
    }

    @Override
    public HasClickHandlers getCloseButton() {
        return closeButton;
    }

    @Override
    public HasClickHandlers getExecuteGuestCommandButton() {
        return executeGuestCommandButton;
    }

    @Override
    public HasClickHandlers getApplyNetworkSettingsButton() {
        return applyNetworkSettingsButton;
    }

    @Override
    public HasClickHandlers getRefreshNetworkAdaptersButton() {
        return refreshNetworkAdaptersButton;
    }

    @Override
    public void clearNetworkAdapters() {
        networkAdapter.clear();
    }

    @Override
    public void addNetworkAdapter(String label, String macAddress) {
        networkAdapter.addItem(label, macAddress);
    }

    @Override
    public String getSelectedMacAddress() {
        int selected = networkAdapter.getSelectedIndex();
        return selected < 0 ? "" : networkAdapter.getValue(selected); //$NON-NLS-1$
    }

    @Override
    public boolean isNetworkEnabled() {
        return enableNetworkRadioButton.getValue();
    }

    @Override
    public String getIpAddress() {
        return ipAddress.getText().trim();
    }

    @Override
    public String getSubnetMask() {
        return subnetMask.getText().trim();
    }

    @Override
    public String getGateway() {
        return gateway.getText().trim();
    }

    @Override
    public void setNetworkSettingsResult(String result) {
        networkSettingsResult.setText(result);
    }

    @Override
    public HasClickHandlers getApplyFileSharingSettingsButton() {
        return applyFileSharingSettingsButton;
    }

    @Override
    public boolean isFileSharingBlocked() {
        return blockFileSharingRadioButton.getValue();
    }

    @Override
    public void setFileSharingSettingsResult(String result) {
        fileSharingSettingsResult.setText(result);
    }

    @Override
    public HasClickHandlers getApplyManagementBlockButton() {
        return applyManagementBlockButton;
    }

    @Override
    public boolean isManagementCommandsBlocked() {
        return blockManagementCommandsRadioButton.getValue();
    }

    @Override
    public void setManagementBlockResult(String result) {
        managementBlockResult.setText(result);
    }

    @Override
    public HasClickHandlers getRefreshGuestEventsButton() {
        return refreshGuestEventsButton;
    }

    @Override
    public void setGuestEvents(List<String[]> events) {
        guestEvents.clear();
        guestEvents.addAll(events);
        guestEventsMessage.setText(events.isEmpty() ? constants.vmSecurityNoEvents() : ""); //$NON-NLS-1$
        drawGuestEvents();
    }

    @Override
    public void setGuestEventsMessage(String message) {
        guestEventsMessage.setText(message);
    }

    @Override
    public String getVmId() {
        return vmId.getText();
    }

    @Override
    public String getGuestCommandPath() {
        return guestCommandPath.getText();
    }

    @Override
    public boolean isAppLockerEnabled() {
        return enableAppLockerRadioButton.getValue();
    }

    @Override
    public void setGuestCommandResult(String result) {
        guestCommandResult.setText(result);
    }

    @Override
    public void setVmId(String value) {
        vmId.setText(value);
    }

    @Override
    public HasClickHandlers getCloseIconButton() {
        return asWidget().getCloseIconButton();
    }

    @Override
    public HandlerRegistration setPopupKeyPressHandler(PopupNativeKeyPressHandler handler) {
        return asWidget().setKeyPressHandler(handler);
    }
}
