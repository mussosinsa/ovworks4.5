package org.ovirt.engine.ui.webadmin.section.main.presenter;

import org.ovirt.engine.ui.common.auth.CurrentUser;
import org.ovirt.engine.ui.common.presenter.AbstractPopupPresenterWidget;
import org.ovirt.engine.ui.common.system.EngineRpmVersionData;

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

    /** The product release shown in front of the engine package version. */
    static final String PRODUCT_VERSION = "OV-Works 2.4"; //$NON-NLS-1$

    private final CurrentUser user;

    @Inject
    public AboutPopupPresenterWidget(EventBus eventBus, ViewDef view, CurrentUser user) {
        super(eventBus, view);
        this.user = user;
    }

    @Override
    protected void onReveal() {
        super.onReveal();

        getView().setVersion(versionText(EngineRpmVersionData.getVersion()));
        getView().setUserName(user.getFullUserName());
    }

    /** "OV-Works 2.4, 4.5.6-1.el9": the product release, then the engine package version. */
    static String versionText(String rpmVersion) {
        if (rpmVersion == null || rpmVersion.trim().isEmpty()) {
            return PRODUCT_VERSION;
        }
        return PRODUCT_VERSION + ", " + rpmVersion.trim(); //$NON-NLS-1$
    }

}
