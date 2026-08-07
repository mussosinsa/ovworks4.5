package org.ovirt.engine.ui.webadmin.section.main.view.popup.user;

import org.ovirt.engine.ui.common.editor.UiCommonEditorDriver;
import org.ovirt.engine.ui.common.idhandler.ElementIdHandler;
import org.ovirt.engine.ui.common.idhandler.WithElementId;
import org.ovirt.engine.ui.common.view.popup.AbstractModelBoundPopupView;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogPanel;
import org.ovirt.engine.ui.common.widget.editor.generic.StringEntityModelPasswordBoxEditor;
import org.ovirt.engine.ui.uicommonweb.models.users.UserPasswordResetModel;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.user.UserPasswordResetPopupPresenterWidget;

import com.google.gwt.core.client.GWT;
import com.google.gwt.editor.client.Editor.Ignore;
import com.google.gwt.editor.client.Editor.Path;
import com.google.gwt.event.shared.EventBus;
import com.google.gwt.safehtml.shared.SafeHtmlUtils;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.user.client.ui.HTML;
import com.google.inject.Inject;

public class UserPasswordResetPopupView extends AbstractModelBoundPopupView<UserPasswordResetModel>
        implements UserPasswordResetPopupPresenterWidget.ViewDef {

    interface Driver extends UiCommonEditorDriver<UserPasswordResetModel, UserPasswordResetPopupView> {
    }

    interface ViewUiBinder extends UiBinder<SimpleDialogPanel, UserPasswordResetPopupView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    interface ViewIdHandler extends ElementIdHandler<UserPasswordResetPopupView> {
        ViewIdHandler idHandler = GWT.create(ViewIdHandler.class);
    }

    @UiField
    @Ignore
    HTML messageLabel;

    @UiField(provided = true)
    @Path(value = "password.entity")
    @WithElementId
    StringEntityModelPasswordBoxEditor passwordEditor;

    private final Driver driver = GWT.create(Driver.class);

    @Inject
    public UserPasswordResetPopupView(EventBus eventBus) {
        super(eventBus);
        initEditors();
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        ViewIdHandler.idHandler.generateAndSetIds(this);
        driver.initialize(this);
    }

    void initEditors() {
        passwordEditor = new StringEntityModelPasswordBoxEditor();
    }

    @Override
    public void edit(UserPasswordResetModel object) {
        driver.edit(object);
    }

    @Override
    public UserPasswordResetModel flush() {
        return driver.flush();
    }

    @Override
    public void cleanup() {
        driver.cleanup();
    }

    @Override
    public void setMessage(String message) {
        if (message != null && !message.isEmpty()) {
            messageLabel.setHTML(SafeHtmlUtils.fromString(message).asString().replace("\n", "<br/>")); //$NON-NLS-1$ //$NON-NLS-2$
            messageLabel.setVisible(true);
        } else {
            messageLabel.setVisible(false);
        }
    }
}
