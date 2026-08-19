package org.ovirt.engine.ui.webadmin.section.main.view.popup;

import org.ovirt.engine.ui.common.view.AbstractPopupView;
import org.ovirt.engine.ui.common.widget.dialog.PopupNativeKeyPressHandler;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogButton;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogPanel;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.SecuritySettingsPopupPresenterWidget;

import com.google.gwt.core.client.GWT;
import com.google.gwt.event.dom.client.HasClickHandlers;
import com.google.gwt.event.shared.EventBus;
import com.google.gwt.event.shared.HandlerRegistration;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.user.client.ui.Button;
import com.google.gwt.user.client.ui.TextArea;
import com.google.gwt.user.client.ui.TextBox;
import com.google.inject.Inject;

public class SecuritySettingsPopupView extends AbstractPopupView<SimpleDialogPanel> implements SecuritySettingsPopupPresenterWidget.ViewDef {

    interface ViewUiBinder extends UiBinder<SimpleDialogPanel, SecuritySettingsPopupView> {
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

    @Inject
    public SecuritySettingsPopupView(EventBus eventBus) {
        super(eventBus);
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
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
    public String getVmId() {
        return vmId.getText();
    }

    @Override
    public String getGuestCommandPath() {
        return guestCommandPath.getText();
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
