package org.ovirt.engine.ui.common.presenter;

import javax.inject.Inject;

import com.google.web.bindery.event.shared.EventBus;

public class ExpandAllButtonPresenterWidget extends ToggleButtonPresenterWidget {

    public interface ViewDef extends ToggleButtonPresenterWidget.ViewDef {
    }

    @Inject
    public ExpandAllButtonPresenterWidget(EventBus eventBus, ExpandAllButtonPresenterWidget.ViewDef view) {
        super(eventBus, view);
    }
}
