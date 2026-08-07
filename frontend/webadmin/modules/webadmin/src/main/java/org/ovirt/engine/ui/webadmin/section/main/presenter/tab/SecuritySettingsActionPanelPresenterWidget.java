package org.ovirt.engine.ui.webadmin.section.main.presenter.tab;

import javax.inject.Inject;

import org.ovirt.engine.ui.common.presenter.ActionPanelPresenterWidget;
import org.ovirt.engine.ui.common.uicommon.model.MainModelProvider;
import org.ovirt.engine.ui.uicommonweb.models.SecuritySettingsListModel;

import com.google.web.bindery.event.shared.EventBus;

public class SecuritySettingsActionPanelPresenterWidget extends
        ActionPanelPresenterWidget<Void, Object, SecuritySettingsListModel> {

    @Inject
    public SecuritySettingsActionPanelPresenterWidget(EventBus eventBus,
            ActionPanelPresenterWidget.ViewDef<Void, Object> view,
            MainModelProvider<Object, SecuritySettingsListModel> dataProvider) {
        super(eventBus, view, dataProvider);
    }

    @Override
    protected void initializeButtons() {
        // Security settings action buttons will be added here
    }
}
