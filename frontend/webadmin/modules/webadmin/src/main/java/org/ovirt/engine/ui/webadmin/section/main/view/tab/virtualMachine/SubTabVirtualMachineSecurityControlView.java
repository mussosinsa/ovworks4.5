package org.ovirt.engine.ui.webadmin.section.main.view.tab.virtualMachine;

import javax.inject.Inject;

import org.ovirt.engine.core.common.businessentities.VM;
import org.ovirt.engine.ui.common.uicommon.model.DetailModelProvider;
import org.ovirt.engine.ui.common.view.AbstractSubTabFormView;
import org.ovirt.engine.ui.uicommonweb.models.vms.VmGeneralModel;
import org.ovirt.engine.ui.uicommonweb.models.vms.VmListModel;
import org.ovirt.engine.ui.webadmin.section.main.presenter.tab.virtualMachine.SubTabVirtualMachineSecurityControlPresenter;

import com.google.gwt.user.client.ui.Label;

/** Placeholder tab content; selecting the tab immediately reveals the security-control dialog. */
public class SubTabVirtualMachineSecurityControlView
        extends AbstractSubTabFormView<VM, VmListModel<Void>, VmGeneralModel>
        implements SubTabVirtualMachineSecurityControlPresenter.ViewDef {

    @Inject
    public SubTabVirtualMachineSecurityControlView(
            DetailModelProvider<VmListModel<Void>, VmGeneralModel> modelProvider) {
        super(modelProvider);
        initWidget(new Label());
    }

    @Override
    protected void generateIds() {
        // The popup owns all interactive elements.
    }

    @Override
    public void setMainSelectedItem(VM selectedItem) {
        // The presenter reads the current selection before opening the popup.
    }
}
