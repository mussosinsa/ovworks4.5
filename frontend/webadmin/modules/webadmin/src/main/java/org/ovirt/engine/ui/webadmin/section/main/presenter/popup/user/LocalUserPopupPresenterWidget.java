package org.ovirt.engine.ui.webadmin.section.main.presenter.popup.user;

import org.ovirt.engine.ui.common.presenter.AbstractModelBoundPopupPresenterWidget;
import org.ovirt.engine.ui.uicommonweb.models.users.LocalUserModel;

import com.google.gwt.event.shared.EventBus;
import com.google.inject.Inject;

public class LocalUserPopupPresenterWidget extends AbstractModelBoundPopupPresenterWidget<LocalUserModel, LocalUserPopupPresenterWidget.ViewDef> {

    public interface ViewDef extends AbstractModelBoundPopupPresenterWidget.ViewDef<LocalUserModel> {
    }

    @Inject
    public LocalUserPopupPresenterWidget(EventBus eventBus, ViewDef view) {
        super(eventBus, view);
    }
}
