package org.ovirt.engine.ui.webadmin.section.main.presenter.popup.user;

import org.ovirt.engine.ui.common.presenter.AbstractModelBoundPopupPresenterWidget;
import org.ovirt.engine.ui.uicommonweb.models.users.LocalGroupAddModel;

import com.google.gwt.event.shared.EventBus;
import com.google.inject.Inject;

public class LocalGroupAddPopupPresenterWidget extends
        AbstractModelBoundPopupPresenterWidget<LocalGroupAddModel, LocalGroupAddPopupPresenterWidget.ViewDef> {
    public interface ViewDef extends AbstractModelBoundPopupPresenterWidget.ViewDef<LocalGroupAddModel> {
    }

    @Inject
    public LocalGroupAddPopupPresenterWidget(EventBus eventBus, ViewDef view) {
        super(eventBus, view);
    }
}
