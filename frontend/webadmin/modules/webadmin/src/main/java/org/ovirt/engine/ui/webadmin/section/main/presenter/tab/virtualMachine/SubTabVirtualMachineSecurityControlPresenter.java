package org.ovirt.engine.ui.webadmin.section.main.presenter.tab.virtualMachine;

import org.ovirt.engine.core.common.businessentities.VM;
import org.ovirt.engine.ui.common.presenter.AbstractSubTabPresenter;
import org.ovirt.engine.ui.common.uicommon.model.DetailModelProvider;
import org.ovirt.engine.ui.uicommonweb.models.vms.VmGeneralModel;
import org.ovirt.engine.ui.uicommonweb.models.vms.VmListModel;
import org.ovirt.engine.ui.uicommonweb.place.WebAdminApplicationPlaces;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.SecuritySettingsPopupPresenterWidget;
import org.ovirt.engine.ui.webadmin.section.main.presenter.tab.DetailTabDataIndex;

import com.google.gwt.event.shared.EventBus;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.gwtplatform.mvp.client.TabData;
import com.gwtplatform.mvp.client.annotations.NameToken;
import com.gwtplatform.mvp.client.annotations.ProxyCodeSplit;
import com.gwtplatform.mvp.client.annotations.TabInfo;
import com.gwtplatform.mvp.client.proxy.PlaceManager;
import com.gwtplatform.mvp.client.proxy.RevealRootPopupContentEvent;
import com.gwtplatform.mvp.client.proxy.TabContentProxyPlace;

/** Opens the security-control dialog for the VM selected in the main grid. */
public class SubTabVirtualMachineSecurityControlPresenter extends AbstractSubTabVirtualMachinePresenter<VmGeneralModel,
        SubTabVirtualMachineSecurityControlPresenter.ViewDef,
        SubTabVirtualMachineSecurityControlPresenter.ProxyDef> {

    @ProxyCodeSplit
    @NameToken(WebAdminApplicationPlaces.virtualMachineSecurityControlSubTabPlace)
    public interface ProxyDef extends TabContentProxyPlace<SubTabVirtualMachineSecurityControlPresenter> {
    }

    public interface ViewDef extends AbstractSubTabPresenter.ViewDef<VM> {
    }

    @TabInfo(container = VirtualMachineSubTabPanelPresenter.class)
    static TabData getTabData() {
        return DetailTabDataIndex.VIRTUALMACHINE_SECURITY_CONTROL;
    }

    private final VirtualMachineMainSelectedItems selectedItems;
    private final Provider<SecuritySettingsPopupPresenterWidget> popupProvider;

    @Inject
    public SubTabVirtualMachineSecurityControlPresenter(EventBus eventBus, ViewDef view, ProxyDef proxy,
            PlaceManager placeManager, VirtualMachineMainSelectedItems selectedItems,
            DetailModelProvider<VmListModel<Void>, VmGeneralModel> modelProvider,
            Provider<SecuritySettingsPopupPresenterWidget> popupProvider) {
        super(eventBus, view, proxy, placeManager, modelProvider, selectedItems, null,
                VirtualMachineSubTabPanelPresenter.TYPE_SetTabContent);
        this.selectedItems = selectedItems;
        this.popupProvider = popupProvider;
    }

    @Override
    protected void onReveal() {
        super.onReveal();
        VM vm = selectedItems.getSelectedItem();
        if (vm != null) {
            SecuritySettingsPopupPresenterWidget popup = popupProvider.get();
            popup.setVmId(vm.getId());
            RevealRootPopupContentEvent.fire(this, popup);
        }
    }
}
