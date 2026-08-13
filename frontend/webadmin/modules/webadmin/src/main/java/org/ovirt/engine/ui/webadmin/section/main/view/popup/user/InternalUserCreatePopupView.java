package org.ovirt.engine.ui.webadmin.section.main.view.popup.user;

import org.ovirt.engine.ui.common.editor.UiCommonEditorDriver;
import org.ovirt.engine.ui.common.view.popup.AbstractModelBoundPopupView;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogPanel;
import org.ovirt.engine.ui.common.widget.editor.generic.StringEntityModelPasswordBoxEditor;
import org.ovirt.engine.ui.common.widget.editor.generic.StringEntityModelTextBoxEditor;
import org.ovirt.engine.ui.uicommonweb.models.users.InternalUserCreateModel;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.user.InternalUserCreatePopupPresenterWidget;

import com.google.gwt.core.client.GWT;
import com.google.gwt.editor.client.Editor.Path;
import com.google.gwt.event.shared.EventBus;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.inject.Inject;

public class InternalUserCreatePopupView extends AbstractModelBoundPopupView<InternalUserCreateModel>
        implements InternalUserCreatePopupPresenterWidget.ViewDef {

    interface Driver extends UiCommonEditorDriver<InternalUserCreateModel, InternalUserCreatePopupView> {
    }

    interface ViewUiBinder extends UiBinder<SimpleDialogPanel, InternalUserCreatePopupView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    @UiField(provided = true)
    @Path("username.entity") //$NON-NLS-1$
    StringEntityModelTextBoxEditor usernameEditor;

    @UiField(provided = true)
    @Path("firstName.entity") //$NON-NLS-1$
    StringEntityModelTextBoxEditor firstNameEditor;

    @UiField(provided = true)
    @Path("lastName.entity") //$NON-NLS-1$
    StringEntityModelTextBoxEditor lastNameEditor;

    @UiField(provided = true)
    @Path("password.entity") //$NON-NLS-1$
    StringEntityModelPasswordBoxEditor passwordEditor;

    @UiField(provided = true)
    @Path("passwordValidTo.entity") //$NON-NLS-1$
    StringEntityModelTextBoxEditor passwordValidToEditor;

    private final Driver driver = GWT.create(Driver.class);

    @Inject
    public InternalUserCreatePopupView(EventBus eventBus) {
        super(eventBus);
        initEditors();
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        driver.initialize(this);
    }

    private void initEditors() {
        usernameEditor = new StringEntityModelTextBoxEditor();
        firstNameEditor = new StringEntityModelTextBoxEditor();
        lastNameEditor = new StringEntityModelTextBoxEditor();
        passwordEditor = new StringEntityModelPasswordBoxEditor();
        passwordValidToEditor = new StringEntityModelTextBoxEditor();
    }

    @Override
    public void edit(InternalUserCreateModel model) {
        driver.edit(model);
    }

    @Override
    public InternalUserCreateModel flush() {
        return driver.flush();
    }

    @Override
    public void cleanup() {
        driver.cleanup();
    }
}
