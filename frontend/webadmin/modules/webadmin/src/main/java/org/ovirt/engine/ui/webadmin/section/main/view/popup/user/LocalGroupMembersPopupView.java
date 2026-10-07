package org.ovirt.engine.ui.webadmin.section.main.view.popup.user;

import java.util.ArrayList;
import java.util.List;

import org.ovirt.engine.ui.common.view.popup.AbstractModelBoundPopupView;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogPanel;
import org.ovirt.engine.ui.uicommonweb.models.users.LocalGroupMembersModel;
import org.ovirt.engine.ui.uicompat.EventArgs;
import org.ovirt.engine.ui.uicompat.IEventListener;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.user.LocalGroupMembersPopupPresenterWidget;

import com.google.gwt.core.client.GWT;
import com.google.gwt.event.dom.client.ClickEvent;
import com.google.gwt.event.dom.client.DoubleClickEvent;
import com.google.gwt.event.shared.EventBus;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.uibinder.client.UiHandler;
import com.google.gwt.user.client.ui.Label;
import com.google.gwt.user.client.ui.ListBox;
import com.google.inject.Inject;

/**
 * The members of a local group: the local users not in it on the left, those in it on the right,
 * moved across with the buttons between them or by double-clicking a name.
 */
public class LocalGroupMembersPopupView extends AbstractModelBoundPopupView<LocalGroupMembersModel>
        implements LocalGroupMembersPopupPresenterWidget.ViewDef {

    interface Binder extends UiBinder<SimpleDialogPanel, LocalGroupMembersPopupView> {
        Binder INSTANCE = GWT.create(Binder.class);
    }

    @UiField
    ListBox availableList;

    @UiField
    ListBox membersList;

    @UiField
    Label availableCount;

    @UiField
    Label membersCount;

    private LocalGroupMembersModel model;

    private final IEventListener<EventArgs> listsChanged = (ev, sender, args) -> refill();

    @Inject
    public LocalGroupMembersPopupView(EventBus eventBus) {
        super(eventBus);
        initWidget(Binder.INSTANCE.createAndBindUi(this));
        availableList.setMultipleSelect(true);
        membersList.setMultipleSelect(true);
    }

    @UiHandler("addButton")
    void onAdd(ClickEvent event) {
        if (model != null) {
            model.moveToMembers(selected(availableList));
        }
    }

    @UiHandler("removeButton")
    void onRemove(ClickEvent event) {
        if (model != null) {
            model.moveToAvailable(selected(membersList));
        }
    }

    @UiHandler("availableList")
    void onAvailableDoubleClick(DoubleClickEvent event) {
        onAdd(null);
    }

    @UiHandler("membersList")
    void onMembersDoubleClick(DoubleClickEvent event) {
        onRemove(null);
    }

    private static List<String> selected(ListBox list) {
        List<String> result = new ArrayList<>();
        for (int i = 0; i < list.getItemCount(); i++) {
            if (list.isItemSelected(i)) {
                result.add(list.getValue(i));
            }
        }
        return result;
    }

    private void refill() {
        fill(availableList, model.getAvailable());
        fill(membersList, model.getMembers());
        availableCount.setText(model.getAvailable().size() + "명"); //$NON-NLS-1$
        membersCount.setText(model.getMembers().size() + "명"); //$NON-NLS-1$
    }

    private static void fill(ListBox list, List<String> users) {
        list.clear();
        for (String user : users) {
            list.addItem(user, user);
        }
    }

    @Override
    public void edit(LocalGroupMembersModel model) {
        this.model = model;
        model.getListsChangedEvent().addListener(listsChanged);
        refill();
    }

    @Override
    public LocalGroupMembersModel flush() {
        return model;
    }

    @Override
    public void cleanup() {
        if (model != null) {
            model.getListsChangedEvent().removeListener(listsChanged);
            model = null;
        }
    }
}
