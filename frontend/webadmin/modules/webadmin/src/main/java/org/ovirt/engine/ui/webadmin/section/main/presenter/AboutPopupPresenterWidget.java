package org.ovirt.engine.ui.webadmin.section.main.presenter;

import org.ovirt.engine.ui.common.auth.CurrentUser;
import org.ovirt.engine.ui.common.presenter.AbstractPopupPresenterWidget;

import com.google.gwt.event.shared.EventBus;
import com.google.inject.Inject;

/**
 * WebAdmin about dialog
 */
public class AboutPopupPresenterWidget extends AbstractPopupPresenterWidget<AboutPopupPresenterWidget.ViewDef> {

    public interface ViewDef extends AbstractPopupPresenterWidget.ViewDef {

        void setVersion(String version);

        void setUserName(String userName);

    }

    /**
     * The software version shown in the About dialog.
     *
     * <p>Fixed here in WebAdmin on purpose: it is what the portal displays and is independent of
     * the engine package version the backend reports (ProductRPMVersion). Changing the displayed
     * version therefore needs only this portal - no backend rebuild and no engine-setup run.</p>
     */
    static final String DISPLAY_VERSION = "OV-Works Engine 4.5.7-1.el9"; //$NON-NLS-1$

    private final CurrentUser user;

    @Inject
    public AboutPopupPresenterWidget(EventBus eventBus, ViewDef view, CurrentUser user) {
        super(eventBus, view);
        this.user = user;
    }

    @Override
    protected void onReveal() {
        super.onReveal();

        getView().setVersion(versionText());
        getView().setUserName(user.getFullUserName());
    }

    /** The fixed WebAdmin display version, e.g. "OV-Works Engine 4.5.7-1.el9". */
    static String versionText() {
        return DISPLAY_VERSION;
    }

}
