package org.ovirt.engine.ui.uicommonweb.models;

import java.util.ArrayList;
import java.util.List;

import org.ovirt.engine.core.common.action.ActionParametersBase;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.ui.frontend.Frontend;
import org.ovirt.engine.ui.uicommonweb.UICommand;

public class SecuritySettingsListModel extends ListWithDetailsModel {

    private UICommand securityAuditCommand;
    private UICommand integrityVerificationCommand;
    private UICommand fullLogBackupCommand;
    private UICommand remoteBackupCommand;
    private UICommand engineBackupCommand;

    public UICommand getSecurityAuditCommand() {
        return securityAuditCommand;
    }

    private void setSecurityAuditCommand(UICommand value) {
        securityAuditCommand = value;
    }

    public UICommand getIntegrityVerificationCommand() {
        return integrityVerificationCommand;
    }

    private void setIntegrityVerificationCommand(UICommand value) {
        integrityVerificationCommand = value;
    }

    public UICommand getFullLogBackupCommand() {
        return fullLogBackupCommand;
    }

    private void setFullLogBackupCommand(UICommand value) {
        fullLogBackupCommand = value;
    }

    public UICommand getRemoteBackupCommand() {
        return remoteBackupCommand;
    }

    private void setRemoteBackupCommand(UICommand value) {
        remoteBackupCommand = value;
    }

    public UICommand getEngineBackupCommand() {
        return engineBackupCommand;
    }

    private void setEngineBackupCommand(UICommand value) {
        engineBackupCommand = value;
    }

    public SecuritySettingsListModel() {
        super();
        setTitle("Security Settings"); //$NON-NLS-1$
        // HelpTag setHelpTag(HelpTag.content);
        setHashName("security_settings"); //$NON-NLS-1$

        // Initialize commands
        setSecurityAuditCommand(new UICommand("SecurityAudit", this)); //$NON-NLS-1$
        setIntegrityVerificationCommand(new UICommand("IntegrityVerification", this)); //$NON-NLS-1$
        setFullLogBackupCommand(new UICommand("FullLogBackup", this)); //$NON-NLS-1$
        setRemoteBackupCommand(new UICommand("RemoteBackup", this)); //$NON-NLS-1$
        setEngineBackupCommand(new UICommand("EngineBackup", this)); //$NON-NLS-1$

        // Initialize with dummy items to display the view
        initializeItems();
    }

    private void initializeItems() {
        List<Object> items = new ArrayList<>();
        items.add(new Object()); // Add a placeholder item to make the view visible
        setItems(items);
    }

    @Override
    protected void onEntityChanged() {
        super.onEntityChanged();
    }

    @Override
    protected void syncSearch() {
        super.syncSearch();
        // Refresh items
        initializeItems();
    }

    @Override
    protected Object provideDetailModelEntity(Object selectedItem) {
        return selectedItem;
    }

    @Override
    protected String getListName() {
        return "SecuritySettingsListModel"; //$NON-NLS-1$
    }

    @Override
    public void executeCommand(UICommand command) {
        super.executeCommand(command);

        if (command == getSecurityAuditCommand()) {
            executeSecurityAudit();
        } else if (command == getIntegrityVerificationCommand()) {
            executeIntegrityVerification();
        } else if (command == getFullLogBackupCommand()) {
            executeFullLogBackup();
        } else if (command == getRemoteBackupCommand()) {
            executeRemoteBackup();
        } else if (command == getEngineBackupCommand()) {
            executeEngineBackup();
        }
    }

    private void executeSecurityAudit() {
        Frontend.getInstance().runAction(
            ActionType.SecurityAudit,
            new ActionParametersBase(),
            result -> {
                // Handle result if needed
                if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                    // Audit completed successfully
                } else {
                    // Audit failed
                }
            }
        );
    }

    private void executeIntegrityVerification() {
        Frontend.getInstance().runAction(
            ActionType.IntegrityVerification,
            new ActionParametersBase(),
            result -> {
                // Handle result if needed
                if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                    // Verification completed successfully
                } else {
                    // Verification failed
                }
            }
        );
    }

    private void executeFullLogBackup() {
        Frontend.getInstance().runAction(
            ActionType.FullLogBackup,
            new ActionParametersBase(),
            result -> {
                // Handle result if needed
                if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                    // Full log backup completed successfully
                } else {
                    // Full log backup failed
                }
            }
        );
    }

    private void executeRemoteBackup() {
        Frontend.getInstance().runAction(
            ActionType.RemoteBackup,
            new ActionParametersBase(),
            result -> {
                // Handle result if needed
                if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                    // Remote backup completed successfully
                } else {
                    // Remote backup failed
                }
            }
        );
    }

    private void executeEngineBackup() {
        Frontend.getInstance().runAction(
            ActionType.EngineBackup,
            new ActionParametersBase(),
            result -> {
                // Handle result if needed
                if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                    // Engine backup completed successfully
                } else {
                    // Engine backup failed
                }
            }
        );
    }
}
