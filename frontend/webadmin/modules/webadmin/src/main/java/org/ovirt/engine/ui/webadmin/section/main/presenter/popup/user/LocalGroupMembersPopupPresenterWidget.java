package org.ovirt.engine.ui.webadmin.section.main.presenter.popup.user;

import org.ovirt.engine.ui.common.presenter.AbstractModelBoundPopupPresenterWidget;
import org.ovirt.engine.ui.uicommonweb.models.users.LocalGroupMembersModel;

import com.google.gwt.event.shared.EventBus;
import com.google.inject.Inject;

public class LocalGroupMembersPopupPresenterWidget extends
        AbstractModelBoundPopupPresenterWidget<LocalGroupMembersModel, LocalGroupMembersPopupPresenterWidget.ViewDef> {
    public interface ViewDef extends AbstractModelBoundPopupPresenterWidget.ViewDef<LocalGroupMembersModel> {
    }

    @Inject
    public LocalGroupMembersPopupPresenterWidget(EventBus eventBus, ViewDef view) {
        super(eventBus, view);
    }
}
