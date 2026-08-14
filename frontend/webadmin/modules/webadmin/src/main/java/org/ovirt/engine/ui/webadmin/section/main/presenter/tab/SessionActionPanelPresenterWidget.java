package org.ovirt.engine.ui.webadmin.section.main.presenter.tab;

import javax.inject.Inject;

import org.gwtbootstrap3.client.ui.Button;
import org.gwtbootstrap3.client.ui.constants.ButtonType;
import org.ovirt.engine.core.common.businessentities.UserSession;
import org.ovirt.engine.ui.common.presenter.ActionPanelPresenterWidget;
import org.ovirt.engine.ui.common.uicommon.model.MainModelProvider;
import org.ovirt.engine.ui.common.widget.action.ActionButton;
import org.ovirt.engine.ui.uicommonweb.UICommand;
import org.ovirt.engine.ui.uicommonweb.models.SessionListModel;
import org.ovirt.engine.ui.webadmin.ApplicationConstants;
import org.ovirt.engine.ui.webadmin.gin.AssetProvider;
import org.ovirt.engine.ui.webadmin.widget.action.WebAdminButtonDefinition;

import com.google.gwt.user.client.ui.PopupPanel;
import com.google.gwt.user.client.ui.VerticalPanel;
import com.google.web.bindery.event.shared.EventBus;

public class SessionActionPanelPresenterWidget extends ActionPanelPresenterWidget<UserSession, UserSession, SessionListModel> {

    private static final String SESSION_LIMIT_BUTTON_ID = "sessionLimit"; //$NON-NLS-1$
    private static final ApplicationConstants constants = AssetProvider.getConstants();

    private PopupPanel sessionLimitPopup;
    private ActionButton sessionLimitButton;
    private int selectedSessionLimit = 1;

    @Inject
    public SessionActionPanelPresenterWidget(EventBus eventBus,
            ActionPanelPresenterWidget.ViewDef<UserSession, UserSession> view,
            MainModelProvider<UserSession, SessionListModel> dataProvider) {
        super(eventBus, view, dataProvider);
    }

    @Override
    protected void initializeButtons() {
        SessionLimitButtonDefinition sessionLimitButtonDefinition = new SessionLimitButtonDefinition();
        addActionButton(sessionLimitButtonDefinition);
        sessionLimitButton = getView().getActionItems().get(sessionLimitButtonDefinition);
        initSessionLimitPopup();
        updateSessionLimitButton();

        addActionButton(new WebAdminButtonDefinition<UserSession, UserSession>(constants.terminateSession()) {
            @Override
            protected UICommand resolveCommand() {
                return getModel().getTerminateCommand();
            }
        });
    }

    private void initSessionLimitPopup() {
        sessionLimitPopup = new PopupPanel(true);
        sessionLimitPopup.setAutoHideEnabled(true);

        VerticalPanel popupContents = new VerticalPanel();
        popupContents.setSpacing(4);

        addSessionLimitOption(popupContents, 1);
        addSessionLimitOption(popupContents, 2);
        addSessionLimitOption(popupContents, 3);
        addSessionLimitOption(popupContents, 4);
        addSessionLimitOption(popupContents, 5);

        sessionLimitPopup.setWidget(popupContents);
    }

    private void addSessionLimitOption(VerticalPanel popupContents, int option) {
        Button optionButton = new Button(Integer.toString(option));
        optionButton.setType(ButtonType.DEFAULT);
        optionButton.setBlock(true);
        optionButton.addClickHandler(event -> {
            selectedSessionLimit = option;
            updateSessionLimitButton();
            sessionLimitPopup.hide();
            if (getModel().getSetSessionLimitCommand() != null) {
                getModel().setSessionLimit(selectedSessionLimit);
                getModel().getSetSessionLimitCommand().execute();
            }
        });
        popupContents.add(optionButton);
    }

    private void showSessionLimitPopup() {
        if (sessionLimitButton != null) {
            sessionLimitPopup.showRelativeTo(sessionLimitButton.asWidget());
        }
    }

    private void updateSessionLimitButton() {
        if (sessionLimitButton != null) {
            sessionLimitButton.setText(constants.concurrentSessionLimit() + ": " + selectedSessionLimit); //$NON-NLS-1$
        }
    }

    private class SessionLimitButtonDefinition extends WebAdminButtonDefinition<UserSession, UserSession> {
        SessionLimitButtonDefinition() {
            super(constants.concurrentSessionLimit());
        }

        @Override
        public void onClick(UserSession mainEntity, java.util.List<UserSession> selectedItems) {
            showSessionLimitPopup();
        }

        @Override
        public boolean isEnabled(UserSession mainEntity, java.util.List<UserSession> selectedItems) {
            return selectedItems != null && selectedItems.size() == 1;
        }

        @Override
        public boolean isAccessible(UserSession mainEntity, java.util.List<UserSession> selectedItems) {
            return true;
        }

        @Override
        public int getIndex() {
            return 0;
        }

        @Override
        public String getUniqueId() {
            return SESSION_LIMIT_BUTTON_ID;
        }

        @Override
        protected UICommand resolveCommand() {
            return null;
        }
    }

}
