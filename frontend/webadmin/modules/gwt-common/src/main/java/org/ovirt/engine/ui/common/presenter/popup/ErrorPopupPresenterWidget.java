package org.ovirt.engine.ui.common.presenter.popup;

import org.ovirt.engine.ui.common.presenter.AbstractPopupPresenterWidget;

import com.google.gwt.event.shared.EventBus;
import com.google.inject.Inject;

/**
 * Implements the default error dialog.
 */
public class ErrorPopupPresenterWidget extends AbstractPopupPresenterWidget<ErrorPopupPresenterWidget.ViewDef> {

    public interface ViewDef extends AbstractPopupPresenterWidget.ViewDef {

        void setErrorMessage(String errorMessage);

        /** @param caption the window's title, or null for the error caption */
        void setCaption(String caption);

    }

    @Inject
    public ErrorPopupPresenterWidget(EventBus eventBus, ViewDef view) {
        super(eventBus, view);
    }

    public void prepare(String errorMessage) {
        prepare(errorMessage, null);
    }

    /**
     * @param caption the window's title, or null for the error caption. Set every time: the
     *        window is reused, and a title given once must not stay on the next error.
     */
    public void prepare(String message, String caption) {
        getView().setCaption(caption);
        getView().setErrorMessage(message);
    }

    @Override
    protected void handleEnterKey() {
        onClose();
    }

}
