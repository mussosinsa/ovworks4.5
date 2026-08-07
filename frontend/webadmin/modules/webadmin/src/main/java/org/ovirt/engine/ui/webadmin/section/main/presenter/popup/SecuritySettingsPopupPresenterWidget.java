package org.ovirt.engine.ui.webadmin.section.main.presenter.popup;

import org.ovirt.engine.ui.common.presenter.AbstractPopupPresenterWidget;

import com.google.gwt.event.shared.EventBus;
import com.google.inject.Inject;

/**
 * Implements the Security Settings popup dialog.
 */
public class SecuritySettingsPopupPresenterWidget extends AbstractPopupPresenterWidget<SecuritySettingsPopupPresenterWidget.ViewDef> {

    public interface ViewDef extends AbstractPopupPresenterWidget.ViewDef {
        void setIntegrityCheckHandler(Runnable handler);
        void setClientManagementHandler(Runnable handler);
    }

    @Inject
    public SecuritySettingsPopupPresenterWidget(EventBus eventBus, ViewDef view) {
        super(eventBus, view);
    }
}
