package org.ovirt.engine.ui.webadmin.section.main.presenter.popup.user;

import org.ovirt.engine.ui.common.presenter.AbstractModelBoundPopupPresenterWidget;
import org.ovirt.engine.ui.uicommonweb.models.users.VmPermissionModel;

import com.google.gwt.event.shared.EventBus;
import com.google.inject.Inject;

public class VmPermissionPopupPresenterWidget extends
        AbstractModelBoundPopupPresenterWidget<VmPermissionModel, VmPermissionPopupPresenterWidget.ViewDef> {
    public interface ViewDef extends AbstractModelBoundPopupPresenterWidget.ViewDef<VmPermissionModel> {
    }

    @Inject
    public VmPermissionPopupPresenterWidget(EventBus eventBus, ViewDef view) {
        super(eventBus, view);
    }
}
