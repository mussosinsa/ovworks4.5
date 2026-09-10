package org.ovirt.engine.ui.webadmin.section.main.view.popup.user;

import org.ovirt.engine.ui.common.editor.UiCommonEditorDriver;
import org.ovirt.engine.ui.common.view.popup.AbstractModelBoundPopupView;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogPanel;
import org.ovirt.engine.ui.common.widget.editor.generic.StringEntityModelPasswordBoxEditor;
import org.ovirt.engine.ui.common.widget.editor.generic.StringEntityModelTextBoxEditor;
import org.ovirt.engine.ui.uicommonweb.models.users.LocalUserAddModel;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.user.LocalUserAddPopupPresenterWidget;

import com.google.gwt.core.client.GWT;
import com.google.gwt.editor.client.Editor.Path;
import com.google.gwt.event.shared.EventBus;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.user.client.ui.HTMLPanel;
import com.google.inject.Inject;

public class LocalUserAddPopupView extends AbstractModelBoundPopupView<LocalUserAddModel>
        implements LocalUserAddPopupPresenterWidget.ViewDef {
    interface Driver extends UiCommonEditorDriver<LocalUserAddModel, LocalUserAddPopupView> {
    }

    interface Binder extends UiBinder<SimpleDialogPanel, LocalUserAddPopupView> {
        Binder INSTANCE = GWT.create(Binder.class);
    }

    @UiField(provided = true)
    @Path("userName.entity") //$NON-NLS-1$
    StringEntityModelTextBoxEditor userNameEditor;

    @UiField(provided = true)
    @Path("firstName.entity") //$NON-NLS-1$
    StringEntityModelTextBoxEditor firstNameEditor;

    @UiField(provided = true)
    @Path("lastName.entity") //$NON-NLS-1$
    StringEntityModelTextBoxEditor lastNameEditor;

    @UiField(provided = true)
    @Path("password.entity") //$NON-NLS-1$
    StringEntityModelPasswordBoxEditor passwordEditor;

    @UiField
    HTMLPanel passwordHint;

    @UiField(provided = true)
    @Path("passwordValidTo.entity") //$NON-NLS-1$
    StringEntityModelTextBoxEditor passwordValidToEditor;

    @UiField(provided = true)
    @Path("email.entity") //$NON-NLS-1$
    StringEntityModelTextBoxEditor emailEditor;

    private final Driver driver = GWT.create(Driver.class);

    @Inject
    public LocalUserAddPopupView(EventBus eventBus) {
        super(eventBus);
        userNameEditor = new StringEntityModelTextBoxEditor();
        firstNameEditor = new StringEntityModelTextBoxEditor();
        lastNameEditor = new StringEntityModelTextBoxEditor();
        passwordEditor = new StringEntityModelPasswordBoxEditor();
        passwordValidToEditor = new StringEntityModelTextBoxEditor();
        emailEditor = new StringEntityModelTextBoxEditor();
        initWidget(Binder.INSTANCE.createAndBindUi(this));
        driver.initialize(this);
    }
    @Override
    public void edit(LocalUserAddModel model) {
        userNameEditor.setEnabled(!model.isEditing());
        passwordEditor.setVisible(!model.isEditing());
        // The policy only applies to the initial password, which editing does not set.
        passwordHint.setVisible(!model.isEditing());
        passwordValidToEditor.setVisible(!model.isEditing());
        emailEditor.setVisible(model.isEditing());
        driver.edit(model);
    }

    @Override
    public LocalUserAddModel flush() {
        return driver.flush();
    }

    @Override
    public void cleanup() {
        driver.cleanup();
    }
}
