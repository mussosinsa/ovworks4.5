package org.ovirt.engine.ui.webadmin.section.main.view.popup.user;

import org.ovirt.engine.ui.common.editor.UiCommonEditorDriver;
import org.ovirt.engine.ui.common.view.popup.AbstractModelBoundPopupView;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogPanel;
import org.ovirt.engine.ui.common.widget.editor.generic.StringEntityModelTextBoxEditor;
import org.ovirt.engine.ui.uicommonweb.models.users.LocalGroupAddModel;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.user.LocalGroupAddPopupPresenterWidget;

import com.google.gwt.core.client.GWT;
import com.google.gwt.editor.client.Editor.Path;
import com.google.gwt.event.shared.EventBus;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.inject.Inject;

public class LocalGroupAddPopupView extends AbstractModelBoundPopupView<LocalGroupAddModel>
        implements LocalGroupAddPopupPresenterWidget.ViewDef {
    interface Driver extends UiCommonEditorDriver<LocalGroupAddModel, LocalGroupAddPopupView> {
    }

    interface Binder extends UiBinder<SimpleDialogPanel, LocalGroupAddPopupView> {
        Binder INSTANCE = GWT.create(Binder.class);
    }

    @UiField(provided = true)
    @Path("groupName.entity") //$NON-NLS-1$
    StringEntityModelTextBoxEditor groupNameEditor;

    private final Driver driver = GWT.create(Driver.class);

    @Inject
    public LocalGroupAddPopupView(EventBus eventBus) {
        super(eventBus);
        groupNameEditor = new StringEntityModelTextBoxEditor();
        initWidget(Binder.INSTANCE.createAndBindUi(this));
        driver.initialize(this);
    }

    @Override
    public void edit(LocalGroupAddModel model) {
        driver.edit(model);
    }

    @Override
    public LocalGroupAddModel flush() {
        return driver.flush();
    }

    @Override
    public void cleanup() {
        driver.cleanup();
    }
}
