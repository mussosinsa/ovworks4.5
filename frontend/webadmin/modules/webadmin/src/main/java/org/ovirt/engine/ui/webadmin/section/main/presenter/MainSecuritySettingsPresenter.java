package org.ovirt.engine.ui.webadmin.section.main.presenter;

import java.util.List;

import org.ovirt.engine.ui.common.place.PlaceRequestFactory;
import org.ovirt.engine.ui.common.presenter.OvirtBreadCrumbsPresenterWidget;
import org.ovirt.engine.ui.common.uicommon.model.MainModelProvider;
import org.ovirt.engine.ui.uicommonweb.models.SecuritySettingsListModel;
import org.ovirt.engine.ui.uicommonweb.place.WebAdminApplicationPlaces;
import org.ovirt.engine.ui.webadmin.section.main.presenter.tab.SecuritySettingsActionPanelPresenterWidget;

import com.google.gwt.event.shared.EventBus;
import com.google.inject.Inject;
import com.gwtplatform.dispatch.annotation.GenEvent;
import com.gwtplatform.mvp.client.annotations.NameToken;
import com.gwtplatform.mvp.client.annotations.ProxyCodeSplit;
import com.gwtplatform.mvp.client.proxy.PlaceManager;
import com.gwtplatform.mvp.client.proxy.ProxyPlace;
import com.gwtplatform.mvp.shared.proxy.PlaceRequest;

public class MainSecuritySettingsPresenter extends AbstractMainWithDetailsPresenter<Object,
        SecuritySettingsListModel, MainSecuritySettingsPresenter.ViewDef, MainSecuritySettingsPresenter.ProxyDef> {

    @GenEvent
    public class SecuritySettingsSelectionChange {
        List<Object> selectedItems;
    }

    @ProxyCodeSplit
    @NameToken(WebAdminApplicationPlaces.securitySettingsMainPlace)
    public interface ProxyDef extends ProxyPlace<MainSecuritySettingsPresenter> {
    }

    public interface ViewDef extends AbstractMainWithDetailsPresenter.ViewDef<Object> {
    }

    @Inject
    public MainSecuritySettingsPresenter(EventBus eventBus,
            ViewDef view,
            ProxyDef proxy,
            PlaceManager placeManager,
            MainModelProvider<Object, SecuritySettingsListModel> modelProvider,
            SearchPanelPresenterWidget<Object, SecuritySettingsListModel> searchPanelPresenterWidget,
            OvirtBreadCrumbsPresenterWidget<Object, SecuritySettingsListModel> breadCrumbs,
            SecuritySettingsActionPanelPresenterWidget actionPanel) {
        super(eventBus, view, proxy, placeManager, modelProvider, searchPanelPresenterWidget, breadCrumbs, actionPanel);
    }

    @Override
    protected void fireTableSelectionChangeEvent() {
        SecuritySettingsSelectionChangeEvent.fire(this, getSelectedItems());
    }

    @Override
    protected PlaceRequest getMainViewRequest() {
        return PlaceRequestFactory.get(WebAdminApplicationPlaces.securitySettingsMainPlace);
    }

    @Override
    protected boolean hasSelectionDetails() {
        return false;
    }
}
