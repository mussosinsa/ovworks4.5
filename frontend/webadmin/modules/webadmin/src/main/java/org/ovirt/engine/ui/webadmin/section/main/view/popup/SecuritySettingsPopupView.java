package org.ovirt.engine.ui.webadmin.section.main.view.popup;

import org.ovirt.engine.ui.common.view.AbstractPopupView;
import org.ovirt.engine.ui.common.widget.dialog.PopupNativeKeyPressHandler;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogButton;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogPanel;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.SecuritySettingsPopupPresenterWidget;
import org.ovirt.engine.ui.webadmin.section.main.view.popup.security.ClientManagementView;
import org.ovirt.engine.ui.webadmin.section.main.view.popup.security.IntegrityCheckView;

import com.google.gwt.core.client.GWT;
import com.google.gwt.event.dom.client.HasClickHandlers;
import com.google.gwt.event.shared.EventBus;
import com.google.gwt.event.shared.HandlerRegistration;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.inject.Inject;

public class SecuritySettingsPopupView extends AbstractPopupView<SimpleDialogPanel> implements SecuritySettingsPopupPresenterWidget.ViewDef {

    interface ViewUiBinder extends UiBinder<SimpleDialogPanel, SecuritySettingsPopupView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    @UiField
    SimpleDialogButton closeButton;

    @UiField(provided=true)
    IntegrityCheckView integrityCheckView;

    @UiField(provided=true)
    ClientManagementView clientManagementView;

    @Inject
    public SecuritySettingsPopupView(
            EventBus eventBus,
            IntegrityCheckView integrityCheckView,
            ClientManagementView clientManagementView) {
        super(eventBus);
        this.integrityCheckView = integrityCheckView;
        this.clientManagementView = clientManagementView;
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
    }

    @Override
    public void setIntegrityCheckHandler(Runnable handler) {
        // Not needed with tab-based navigation
    }

    @Override
    public void setClientManagementHandler(Runnable handler) {
        // Not needed with tab-based navigation
    }

    @Override
    public HasClickHandlers getCloseButton() {
        return closeButton;
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
