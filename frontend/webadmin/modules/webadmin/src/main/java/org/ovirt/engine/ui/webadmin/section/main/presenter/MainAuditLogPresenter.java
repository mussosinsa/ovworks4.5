package org.ovirt.engine.ui.webadmin.section.main.presenter;

import java.util.List;

import org.ovirt.engine.ui.common.place.PlaceRequestFactory;
import org.ovirt.engine.ui.common.presenter.OvirtBreadCrumbsPresenterWidget;
import org.ovirt.engine.ui.common.uicommon.model.MainModelProvider;
import org.ovirt.engine.ui.uicommonweb.models.AuditLogListModel;
import org.ovirt.engine.ui.webadmin.section.main.presenter.tab.AuditLogActionPanelPresenterWidget;

import com.google.gwt.event.shared.EventBus;
import com.google.inject.Inject;
import com.gwtplatform.dispatch.annotation.GenEvent;
import com.gwtplatform.mvp.client.annotations.NameToken;
import com.gwtplatform.mvp.client.annotations.ProxyCodeSplit;
import com.gwtplatform.mvp.client.proxy.PlaceManager;
import com.gwtplatform.mvp.client.proxy.ProxyPlace;
import com.gwtplatform.mvp.shared.proxy.PlaceRequest;

public class MainAuditLogPresenter extends AbstractMainWithDetailsPresenter<Object,
        AuditLogListModel, MainAuditLogPresenter.ViewDef, MainAuditLogPresenter.ProxyDef> {

    @GenEvent
    public class AuditLogSelectionChange {
        List<Object> selectedItems;
    }

    @ProxyCodeSplit
    @NameToken("allbackup") //$NON-NLS-1$
    public interface ProxyDef extends ProxyPlace<MainAuditLogPresenter> {
    }

    public interface ViewDef extends AbstractMainWithDetailsPresenter.ViewDef<Object> {
    }

    @Inject
    public MainAuditLogPresenter(EventBus eventBus,
            ViewDef view,
            ProxyDef proxy,
            PlaceManager placeManager,
            MainModelProvider<Object, AuditLogListModel> modelProvider,
            SearchPanelPresenterWidget<Object, AuditLogListModel> searchPanelPresenterWidget,
            OvirtBreadCrumbsPresenterWidget<Object, AuditLogListModel> breadCrumbs,
            AuditLogActionPanelPresenterWidget actionPanel) {
        super(eventBus, view, proxy, placeManager, modelProvider, searchPanelPresenterWidget, breadCrumbs, actionPanel);
    }

    @Override
    protected void fireTableSelectionChangeEvent() {
        AuditLogSelectionChangeEvent.fire(this, getSelectedItems());
    }

    @Override
    protected PlaceRequest getMainViewRequest() {
        return PlaceRequestFactory.get("allbackup"); //$NON-NLS-1$
    }

    @Override
    protected boolean hasSelectionDetails() {
        return false;
    }
}
