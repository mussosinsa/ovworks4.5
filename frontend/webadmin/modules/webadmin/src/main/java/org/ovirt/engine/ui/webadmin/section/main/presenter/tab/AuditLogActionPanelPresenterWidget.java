package org.ovirt.engine.ui.webadmin.section.main.presenter.tab;

import javax.inject.Inject;

import org.ovirt.engine.ui.common.presenter.ActionPanelPresenterWidget;
import org.ovirt.engine.ui.common.uicommon.model.MainModelProvider;
import org.ovirt.engine.ui.uicommonweb.models.AuditLogListModel;

import com.google.web.bindery.event.shared.EventBus;

public class AuditLogActionPanelPresenterWidget extends
        ActionPanelPresenterWidget<Void, Object, AuditLogListModel> {

    @Inject
    public AuditLogActionPanelPresenterWidget(EventBus eventBus,
            ActionPanelPresenterWidget.ViewDef<Void, Object> view,
            MainModelProvider<Object, AuditLogListModel> dataProvider) {
        super(eventBus, view, dataProvider);
    }

    @Override
    protected void initializeButtons() {
        // Audit log action buttons will be added here
    }
}
