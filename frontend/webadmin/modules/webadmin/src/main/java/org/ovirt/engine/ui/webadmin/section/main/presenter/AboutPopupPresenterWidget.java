// Modified by 새올정보기술 for OV-Works (2026). Changes against oVirt Engine 4.5.6: docs/ovworks-source-change-statement.md
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

        void setProductName(String productName);

        void setDetailVersion(String detailVersion);

        void setComponentName(String componentName);

        void setUserName(String userName);

    }

    /**
     * The version information shown in the About dialog.
     *
     * <p>Fixed here in WebAdmin on purpose: it is what the portal displays and is independent of
     * the engine package version the backend reports (ProductRPMVersion). Changing it needs only
     * this portal - no backend rebuild and no engine-setup run.</p>
     */
    static final String PRODUCT_NAME = "OV-Works 2.4"; //$NON-NLS-1$
    static final String DETAIL_VERSION = "V2.4.5.9"; //$NON-NLS-1$
    static final String COMPONENT_NAME = "OV-Works Engine 4.5.7-1.el9"; //$NON-NLS-1$

    private final CurrentUser user;

    @Inject
    public AboutPopupPresenterWidget(EventBus eventBus, ViewDef view, CurrentUser user) {
        super(eventBus, view);
        this.user = user;
    }

    @Override
    protected void onReveal() {
        super.onReveal();

        getView().setProductName(PRODUCT_NAME);
        getView().setDetailVersion(DETAIL_VERSION);
        getView().setComponentName(COMPONENT_NAME);
        getView().setUserName(user.getFullUserName());
    }

}
