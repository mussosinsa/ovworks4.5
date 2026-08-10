package org.ovirt.engine.ui.webadmin.section.main.view.popup.user;

import org.ovirt.engine.ui.common.editor.UiCommonEditorDriver;
import org.ovirt.engine.ui.common.idhandler.ElementIdHandler;
import org.ovirt.engine.ui.common.idhandler.WithElementId;
import org.ovirt.engine.ui.common.view.popup.AbstractModelBoundPopupView;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogPanel;
import org.ovirt.engine.ui.common.widget.editor.generic.StringEntityModelPasswordBoxEditor;
import org.ovirt.engine.ui.common.widget.editor.generic.StringEntityModelTextBoxEditor;
import org.ovirt.engine.ui.uicommonweb.models.users.LocalUserModel;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.user.LocalUserPopupPresenterWidget;

import com.google.gwt.core.client.GWT;
import com.google.gwt.editor.client.Editor.Path;
import com.google.gwt.event.shared.EventBus;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.inject.Inject;

public class LocalUserPopupView extends AbstractModelBoundPopupView<LocalUserModel>
        implements LocalUserPopupPresenterWidget.ViewDef {

    interface Driver extends UiCommonEditorDriver<LocalUserModel, LocalUserPopupView> {
    }

    interface ViewUiBinder extends UiBinder<SimpleDialogPanel, LocalUserPopupView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    interface ViewIdHandler extends ElementIdHandler<LocalUserPopupView> {
        ViewIdHandler idHandler = GWT.create(ViewIdHandler.class);
    }

    @UiField
    @Path("username.entity") //$NON-NLS-1$
    @WithElementId
    StringEntityModelTextBoxEditor usernameEditor;

    @UiField
    @Path("firstName.entity") //$NON-NLS-1$
    @WithElementId
    StringEntityModelTextBoxEditor firstNameEditor;

    @UiField
    @Path("lastName.entity") //$NON-NLS-1$
    @WithElementId
    StringEntityModelTextBoxEditor lastNameEditor;

    @UiField(provided = true)
    @Path("password.entity") //$NON-NLS-1$
    @WithElementId
    StringEntityModelPasswordBoxEditor passwordEditor;

    @UiField
    @Path("passwordValidTo.entity") //$NON-NLS-1$
    @WithElementId
    StringEntityModelTextBoxEditor passwordValidToEditor;

    private final Driver driver = GWT.create(Driver.class);

    @Inject
    public LocalUserPopupView(EventBus eventBus) {
        super(eventBus);
        passwordEditor = new StringEntityModelPasswordBoxEditor();
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        ViewIdHandler.idHandler.generateAndSetIds(this);
        driver.initialize(this);
    }

    @Override
    public void edit(LocalUserModel object) {
        driver.edit(object);
    }

    @Override
    public LocalUserModel flush() {
        return driver.flush();
    }

    @Override
    public void cleanup() {
        driver.cleanup();
    }
}
