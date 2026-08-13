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
import com.google.inject.Inject;

public class LocalUserAddPopupView extends AbstractModelBoundPopupView<LocalUserAddModel>
        implements LocalUserAddPopupPresenterWidget.ViewDef {
    interface Driver extends UiCommonEditorDriver<LocalUserAddModel, LocalUserAddPopupView> { }
    interface Binder extends UiBinder<SimpleDialogPanel, LocalUserAddPopupView> {
        Binder INSTANCE = GWT.create(Binder.class);
    }
    @UiField(provided=true) @Path("userName.entity") StringEntityModelTextBoxEditor userNameEditor;
    @UiField(provided=true) @Path("firstName.entity") StringEntityModelTextBoxEditor firstNameEditor;
    @UiField(provided=true) @Path("lastName.entity") StringEntityModelTextBoxEditor lastNameEditor;
    @UiField(provided=true) @Path("password.entity") StringEntityModelPasswordBoxEditor passwordEditor;
    @UiField(provided=true) @Path("passwordValidTo.entity") StringEntityModelTextBoxEditor passwordValidToEditor;
    private final Driver driver = GWT.create(Driver.class);

    @Inject public LocalUserAddPopupView(EventBus eventBus) {
        super(eventBus);
        userNameEditor = new StringEntityModelTextBoxEditor();
        firstNameEditor = new StringEntityModelTextBoxEditor();
        lastNameEditor = new StringEntityModelTextBoxEditor();
        passwordEditor = new StringEntityModelPasswordBoxEditor();
        passwordValidToEditor = new StringEntityModelTextBoxEditor();
        initWidget(Binder.INSTANCE.createAndBindUi(this));
        driver.initialize(this);
    }
    @Override public void edit(LocalUserAddModel model) { driver.edit(model); }
    @Override public LocalUserAddModel flush() { return driver.flush(); }
    @Override public void cleanup() { driver.cleanup(); }
}
