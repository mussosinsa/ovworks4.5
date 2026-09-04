package org.ovirt.engine.ui.webadmin.section.main.view.popup;

import org.ovirt.engine.ui.common.view.AbstractPopupView;
import org.ovirt.engine.ui.common.widget.dialog.PopupNativeKeyPressHandler;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogButton;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogPanel;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.VmSecurityControlPopupPresenterWidget;

import com.google.gwt.core.client.GWT;
import com.google.gwt.event.dom.client.HasClickHandlers;
import com.google.gwt.event.shared.EventBus;
import com.google.gwt.event.shared.HandlerRegistration;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.user.client.ui.Button;
import com.google.gwt.user.client.ui.HTMLPanel;
import com.google.gwt.user.client.ui.Label;
import com.google.gwt.user.client.ui.RadioButton;
import com.google.gwt.user.client.ui.TextArea;
import com.google.gwt.user.client.ui.TextBox;
import com.google.inject.Inject;

public class VmSecurityControlPopupView extends AbstractPopupView<SimpleDialogPanel>
        implements VmSecurityControlPopupPresenterWidget.ViewDef {

    interface ViewUiBinder extends UiBinder<SimpleDialogPanel, VmSecurityControlPopupView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    @UiField
    SimpleDialogButton closeButton;

    @UiField
    SimpleDialogButton applyButton;

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
    public HasClickHandlers getApplyButton() {
        return applyButton;
    }

    @Override
    public HasClickHandlers getApplyNetworkSettingsButton() {
        return applyNetworkSettingsButton;
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
