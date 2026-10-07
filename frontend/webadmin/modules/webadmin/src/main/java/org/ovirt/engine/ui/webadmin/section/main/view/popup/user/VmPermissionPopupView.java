package org.ovirt.engine.ui.webadmin.section.main.view.popup.user;

import org.ovirt.engine.core.common.businessentities.Role;
import org.ovirt.engine.core.common.businessentities.RoleType;
import org.ovirt.engine.core.common.businessentities.VM;
import org.ovirt.engine.ui.common.editor.UiCommonEditorDriver;
import org.ovirt.engine.ui.common.view.popup.AbstractModelBoundPopupView;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogPanel;
import org.ovirt.engine.ui.common.widget.editor.ListModelListBoxEditor;
import org.ovirt.engine.ui.common.widget.renderer.NameRenderer;
import org.ovirt.engine.ui.common.widget.renderer.NullSafeRenderer;
import org.ovirt.engine.ui.uicommonweb.models.users.VmPermissionModel;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.user.VmPermissionPopupPresenterWidget;

import com.google.gwt.core.client.GWT;
import com.google.gwt.editor.client.Editor.Path;
import com.google.gwt.event.shared.EventBus;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.inject.Inject;

/** A virtual machine and a role for a user or group, or a new role for one it already has. */
public class VmPermissionPopupView extends AbstractModelBoundPopupView<VmPermissionModel>
        implements VmPermissionPopupPresenterWidget.ViewDef {

    interface Driver extends UiCommonEditorDriver<VmPermissionModel, VmPermissionPopupView> {
    }

    interface Binder extends UiBinder<SimpleDialogPanel, VmPermissionPopupView> {
        Binder INSTANCE = GWT.create(Binder.class);
    }

    @UiField(provided = true)
    @Path("vm.selectedItem") //$NON-NLS-1$
    ListModelListBoxEditor<VM> vmEditor;

    @UiField(provided = true)
    @Path("role.selectedItem") //$NON-NLS-1$
    ListModelListBoxEditor<Role> roleEditor;

    private final Driver driver = GWT.create(Driver.class);

    @Inject
    public VmPermissionPopupView(EventBus eventBus) {
        super(eventBus);
        vmEditor = new ListModelListBoxEditor<>(new NameRenderer<VM>());
        roleEditor = new ListModelListBoxEditor<>(new NullSafeRenderer<Role>() {
            @Override
            protected String renderNullSafe(Role role) {
                return role.getType() == RoleType.ADMIN
                        ? role.getName() + " (관리자 역할)" //$NON-NLS-1$
                        : role.getName();
            }
        });
        initWidget(Binder.INSTANCE.createAndBindUi(this));
        driver.initialize(this);
    }

    @Override
    public void edit(VmPermissionModel model) {
        driver.edit(model);
    }

    @Override
    public VmPermissionModel flush() {
        return driver.flush();
    }

    @Override
    public void cleanup() {
        driver.cleanup();
    }
}
