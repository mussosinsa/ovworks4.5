package org.ovirt.engine.ui.webadmin.section.main.presenter.popup.user;

import org.ovirt.engine.ui.common.presenter.AbstractModelBoundPopupPresenterWidget;
import org.ovirt.engine.ui.uicommonweb.models.users.InternalUserCreateModel;

import com.google.gwt.event.shared.EventBus;
import com.google.inject.Inject;

public class InternalUserCreatePopupPresenterWidget extends AbstractModelBoundPopupPresenterWidget<InternalUserCreateModel, InternalUserCreatePopupPresenterWidget.ViewDef> {

    public interface ViewDef extends AbstractModelBoundPopupPresenterWidget.ViewDef<InternalUserCreateModel> {
    }

    @Inject
    public InternalUserCreatePopupPresenterWidget(EventBus eventBus, ViewDef view) {
        super(eventBus, view);
    }

}
