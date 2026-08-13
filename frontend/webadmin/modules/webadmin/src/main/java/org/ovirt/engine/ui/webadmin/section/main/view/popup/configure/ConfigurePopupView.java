package org.ovirt.engine.ui.webadmin.section.main.view.popup.configure;

import org.ovirt.engine.ui.common.view.AbstractPopupView;
import org.ovirt.engine.ui.common.widget.dialog.PopupNativeKeyPressHandler;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogButton;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogPanel;
import org.ovirt.engine.ui.common.widget.dialog.tab.DialogTab;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.configure.ConfigurePopupPresenterWidget;
import org.ovirt.engine.ui.webadmin.section.main.view.popup.instancetypes.InstanceTypesView;
import org.ovirt.engine.ui.webadmin.section.main.view.popup.macpool.SharedMacPoolView;
import org.ovirt.engine.ui.webadmin.section.main.view.popup.scheduling.ClusterPolicyView;
import org.ovirt.engine.ui.webadmin.section.main.view.popup.security.ExternalSslView;

import com.google.gwt.core.client.GWT;
import com.google.gwt.event.dom.client.HasClickHandlers;
import com.google.gwt.event.shared.EventBus;
import com.google.gwt.event.shared.HandlerRegistration;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.inject.Inject;

public class ConfigurePopupView extends AbstractPopupView<SimpleDialogPanel> implements ConfigurePopupPresenterWidget.ViewDef {

    interface ViewUiBinder extends UiBinder<SimpleDialogPanel, ConfigurePopupView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    @UiField
    SimpleDialogButton closeButton;

    @UiField
    DialogTab clusterPoliciesTab;

    @UiField(provided=true)
    RoleView roleView;

    @UiField(provided=true)
    SystemPermissionView systemPermissionView;

    @UiField(provided=true)
    ClusterPolicyView clusterPolicyView;

    @UiField(provided=true)
    InstanceTypesView instanceTypesView;

    @UiField(provided=true)
    SharedMacPoolView sharedMacPoolView;

    @UiField(provided=true)
    EnvironmentVariablesView environmentVariablesView;

    @UiField(provided=true)
    UserEnvironmentVariablesView userEnvironmentVariablesView;

    @UiField(provided=true)
    ExternalSslView externalSslView;

    @Inject
    public ConfigurePopupView(
            EventBus eventBus,
            RoleView roleView,
            SystemPermissionView systemPermissionView,
            ClusterPolicyView clusterPolicyView,
            InstanceTypesView instanceTypesView,
            SharedMacPoolView sharedMacPoolView,
            EnvironmentVariablesView environmentVariablesView,
            UserEnvironmentVariablesView userEnvironmentVariablesView,
            ExternalSslView externalSslView) {
        super(eventBus);
        this.roleView = roleView;
        this.systemPermissionView = systemPermissionView;
        this.clusterPolicyView = clusterPolicyView;
        this.instanceTypesView = instanceTypesView;
        this.sharedMacPoolView = sharedMacPoolView;
        this.environmentVariablesView = environmentVariablesView;
        this.userEnvironmentVariablesView = userEnvironmentVariablesView;
        this.externalSslView = externalSslView;

        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
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

    @Override
    public void hideClusterPolicyTab() {
        clusterPoliciesTab.setVisible(false);
    }

}
