package org.ovirt.engine.ui.webadmin.section.main.presenter.popup.user;

import org.ovirt.engine.ui.common.presenter.AbstractModelBoundPopupPresenterWidget;
import org.ovirt.engine.ui.uicommonweb.models.users.LocalUserAddModel;

import com.google.gwt.event.shared.EventBus;
import com.google.inject.Inject;

public class LocalUserAddPopupPresenterWidget extends
        AbstractModelBoundPopupPresenterWidget<LocalUserAddModel, LocalUserAddPopupPresenterWidget.ViewDef> {
    public interface ViewDef extends AbstractModelBoundPopupPresenterWidget.ViewDef<LocalUserAddModel> {
    }

    @Inject
    public LocalUserAddPopupPresenterWidget(EventBus eventBus, ViewDef view) {
        super(eventBus, view);
    }
}
