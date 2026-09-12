package org.ovirt.engine.ui.webadmin.section.main.presenter.tab;

import javax.inject.Inject;

import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.ui.common.presenter.ActionPanelPresenterWidget;
import org.ovirt.engine.ui.common.uicommon.model.MainModelProvider;
import org.ovirt.engine.ui.uicommonweb.UICommand;
import org.ovirt.engine.ui.uicommonweb.models.users.UserListModel;
import org.ovirt.engine.ui.webadmin.ApplicationConstants;
import org.ovirt.engine.ui.webadmin.gin.AssetProvider;
import org.ovirt.engine.ui.webadmin.widget.action.WebAdminButtonDefinition;

import com.google.web.bindery.event.shared.EventBus;

public class UserActionPanelPresenterWidget extends ActionPanelPresenterWidget<Void, DbUser, UserListModel> {

    private static final ApplicationConstants constants = AssetProvider.getConstants();

    private WebAdminButtonDefinition<Void, DbUser> newButtonDefinition;

    @Inject
    public UserActionPanelPresenterWidget(EventBus eventBus,
            ActionPanelPresenterWidget.ViewDef<Void, DbUser> view,
            MainModelProvider<DbUser, UserListModel> dataProvider) {
        super(eventBus, view, dataProvider);
    }

    @Override
    protected void initializeButtons() {
        newButtonDefinition = new WebAdminButtonDefinition<Void, DbUser>(constants.addUser()) {
            @Override
            protected UICommand resolveCommand() {
                return getModel().getAddCommand();
            }
        };
        addActionButton(newButtonDefinition);
        // Add creates an account in the internal provider. This is the other thing, and the only
        // one that makes sense where the accounts live in an external directory.
        addActionButton(new WebAdminButtonDefinition<Void, DbUser>("디렉터리에서 가져오기") { //$NON-NLS-1$
            @Override
            protected UICommand resolveCommand() {
                return getModel().getImportDirectoryElementCommand();
            }
        });
        addActionButton(new WebAdminButtonDefinition<Void, DbUser>(constants.editUser()) {
            @Override
            protected UICommand resolveCommand() {
                return getModel().getEditCommand();
            }
        });
        addActionButton(new WebAdminButtonDefinition<Void, DbUser>(constants.removeUser()) {
            @Override
            protected UICommand resolveCommand() {
                return getModel().getRemoveCommand();
            }
        });
        addActionButton(new WebAdminButtonDefinition<Void, DbUser>("잠금해제") { //$NON-NLS-1$
            @Override
            protected UICommand resolveCommand() {
                return getModel().getUnlockUserCommand();
            }
        });
        addActionButton(new WebAdminButtonDefinition<Void, DbUser>(constants.resetPasswordUser()) {
            @Override
            protected UICommand resolveCommand() {
                return getModel().getResetPasswordCommand();
            }
        });
        addActionButton(new WebAdminButtonDefinition<Void, DbUser>(constants.assignTagsUser()) {
            @Override
            protected UICommand resolveCommand() {
                return getModel().getAssignTagsCommand();
            }
        });
    }

    public WebAdminButtonDefinition<Void, DbUser> getNewButtonDefinition() {
        return newButtonDefinition;
    }

}
