package org.ovirt.engine.ui.webadmin.section.main.view;

import org.ovirt.engine.ui.common.uicommon.model.MainModelProvider;
import org.ovirt.engine.ui.uicommonweb.models.SecuritySettingsListModel;
import org.ovirt.engine.ui.webadmin.section.main.presenter.MainSecuritySettingsPresenter;
import org.ovirt.engine.ui.webadmin.section.main.view.popup.security.ClientManagementView;
import org.ovirt.engine.ui.webadmin.section.main.view.popup.security.ExternalSslView;
import org.ovirt.engine.ui.webadmin.section.main.view.popup.security.IntegrityCheckView;

import com.google.gwt.user.client.ui.FlowPanel;
import com.google.gwt.user.client.ui.HTML;
import com.google.gwt.user.client.ui.SimplePanel;
import com.google.inject.Inject;

public class MainSecuritySettingsView extends AbstractMainWithDetailsTableView<Object, SecuritySettingsListModel>
        implements MainSecuritySettingsPresenter.ViewDef {

    private final IntegrityCheckView integrityCheckView;
    private final ClientManagementView clientManagementView;
    private final ExternalSslView externalSslView;
    private SimplePanel contentPanel;
    private HTML integrityCheckMenuItem;
    private HTML clientManagementMenuItem;
    private HTML externalSslMenuItem;
    private HTML currentActiveMenuItem;

    @Inject
    public MainSecuritySettingsView(MainModelProvider<Object, SecuritySettingsListModel> modelProvider,
            IntegrityCheckView integrityCheckView,
            ClientManagementView clientManagementView,
            ExternalSslView externalSslView) {
        super(modelProvider);

        this.integrityCheckView = integrityCheckView;
        this.clientManagementView = clientManagementView;
        this.externalSslView = externalSslView;

        // Hide the default table to show the custom layout.
        getTable().setVisible(false);

        // Create main container with flexbox layout
        FlowPanel mainContainer = new FlowPanel();
        mainContainer.getElement().getStyle().setProperty("display", "flex"); //$NON-NLS-1$ //$NON-NLS-2$
        mainContainer.getElement().getStyle().setProperty("width", "100%"); //$NON-NLS-1$ //$NON-NLS-2$
        mainContainer.getElement().getStyle().setProperty("minHeight", "600px"); //$NON-NLS-1$ //$NON-NLS-2$

        // Create sidebar
        FlowPanel sidebar = new FlowPanel();
        sidebar.getElement().getStyle().setProperty("width", "250px"); //$NON-NLS-1$ //$NON-NLS-2$
        sidebar.getElement().getStyle().setProperty("backgroundColor", "#ffffff"); //$NON-NLS-1$ //$NON-NLS-2$
        sidebar.getElement().getStyle().setProperty("borderRight", "1px solid #ddd"); //$NON-NLS-1$ //$NON-NLS-2$
        sidebar.getElement().getStyle().setProperty("flexShrink", "0"); //$NON-NLS-1$ //$NON-NLS-2$
        sidebar.getElement().getStyle().setProperty("overflowY", "auto"); //$NON-NLS-1$ //$NON-NLS-2$

        // Create sidebar header
        HTML sidebarHeader = new HTML("보안 설정"); //$NON-NLS-1$
        sidebarHeader.getElement().getStyle().setProperty("padding", "10px 15px"); //$NON-NLS-1$ //$NON-NLS-2$
        sidebarHeader.getElement().getStyle().setProperty("fontSize", "16px"); //$NON-NLS-1$ //$NON-NLS-2$
        sidebarHeader.getElement().getStyle().setProperty("fontWeight", "bold"); //$NON-NLS-1$ //$NON-NLS-2$
        sidebarHeader.getElement().getStyle().setProperty("borderBottom", "1px solid #ddd"); //$NON-NLS-1$ //$NON-NLS-2$
        sidebarHeader.getElement().getStyle().setProperty("backgroundColor", "#f8f8f8"); //$NON-NLS-1$ //$NON-NLS-2$
        sidebar.add(sidebarHeader);

        // External SSL quick shortcut (always visible)
        HTML externalSslShortcut = new HTML("외부 SSL 적용 바로가기"); //$NON-NLS-1$
        externalSslShortcut.getElement().getStyle().setProperty("display", "block"); //$NON-NLS-1$ //$NON-NLS-2$
        externalSslShortcut.getElement().getStyle().setProperty("padding", "10px 15px"); //$NON-NLS-1$ //$NON-NLS-2$
        externalSslShortcut.getElement().getStyle().setProperty("cursor", "pointer"); //$NON-NLS-1$ //$NON-NLS-2$
        externalSslShortcut.getElement().getStyle().setProperty("color", "#1a73e8"); //$NON-NLS-1$ //$NON-NLS-2$
        externalSslShortcut.getElement().getStyle().setProperty("fontWeight", "bold"); //$NON-NLS-1$ //$NON-NLS-2$
        externalSslShortcut.getElement().getStyle().setProperty("borderBottom", "1px solid #e5e5e5"); //$NON-NLS-1$ //$NON-NLS-2$
        externalSslShortcut.addClickHandler(event -> showExternalSsl());
        sidebar.add(externalSslShortcut);

        // Create menu items
        integrityCheckMenuItem = new HTML("무결성 검사"); //$NON-NLS-1$
        integrityCheckMenuItem.setStyleName("security-menu-item security-menu-item-active"); //$NON-NLS-1$
        integrityCheckMenuItem.getElement().getStyle().setProperty("display", "block"); //$NON-NLS-1$ //$NON-NLS-2$
        integrityCheckMenuItem.getElement().getStyle().setProperty("padding", "10px 15px"); //$NON-NLS-1$ //$NON-NLS-2$
        integrityCheckMenuItem.getElement().getStyle().setProperty("cursor", "pointer"); //$NON-NLS-1$ //$NON-NLS-2$
        integrityCheckMenuItem.getElement().getStyle().setProperty("borderBottom", "1px solid #f0f0f0"); //$NON-NLS-1$ //$NON-NLS-2$
        integrityCheckMenuItem.getElement().getStyle().setProperty("backgroundColor", "#337ab7"); //$NON-NLS-1$ //$NON-NLS-2$
        integrityCheckMenuItem.getElement().getStyle().setProperty("color", "white"); //$NON-NLS-1$ //$NON-NLS-2$
        integrityCheckMenuItem.getElement().getStyle().setProperty("fontWeight", "bold"); //$NON-NLS-1$ //$NON-NLS-2$
        sidebar.add(integrityCheckMenuItem);

        clientManagementMenuItem = new HTML("클라이언트 관리"); //$NON-NLS-1$
        clientManagementMenuItem.setStyleName("security-menu-item"); //$NON-NLS-1$
        clientManagementMenuItem.getElement().getStyle().setProperty("display", "block"); //$NON-NLS-1$ //$NON-NLS-2$
        clientManagementMenuItem.getElement().getStyle().setProperty("padding", "10px 15px"); //$NON-NLS-1$ //$NON-NLS-2$
        clientManagementMenuItem.getElement().getStyle().setProperty("cursor", "pointer"); //$NON-NLS-1$ //$NON-NLS-2$
        clientManagementMenuItem.getElement().getStyle().setProperty("borderBottom", "1px solid #f0f0f0"); //$NON-NLS-1$ //$NON-NLS-2$
        sidebar.add(clientManagementMenuItem);

        externalSslMenuItem = new HTML("외부 SSL"); //$NON-NLS-1$
        externalSslMenuItem.setStyleName("security-menu-item"); //$NON-NLS-1$
        externalSslMenuItem.getElement().getStyle().setProperty("display", "block"); //$NON-NLS-1$ //$NON-NLS-2$
        externalSslMenuItem.getElement().getStyle().setProperty("padding", "10px 15px"); //$NON-NLS-1$ //$NON-NLS-2$
        externalSslMenuItem.getElement().getStyle().setProperty("cursor", "pointer"); //$NON-NLS-1$ //$NON-NLS-2$
        externalSslMenuItem.getElement().getStyle().setProperty("borderBottom", "1px solid #f0f0f0"); //$NON-NLS-1$ //$NON-NLS-2$
        sidebar.add(externalSslMenuItem);

        // Add sidebar to main container
        mainContainer.add(sidebar);

        // Create content panel
        contentPanel = new SimplePanel();
        contentPanel.getElement().getStyle().setProperty("flex", "1"); //$NON-NLS-1$ //$NON-NLS-2$
        contentPanel.getElement().getStyle().setProperty("backgroundColor", "#ffffff"); //$NON-NLS-1$ //$NON-NLS-2$
        contentPanel.getElement().getStyle().setProperty("overflowY", "auto"); //$NON-NLS-1$ //$NON-NLS-2$

        // Add content panel to main container
        mainContainer.add(contentPanel);

        // Compose a root panel with the hidden table and the custom layout.
        FlowPanel rootPanel = new FlowPanel();
        rootPanel.add(getTable());
        rootPanel.add(mainContainer);

        // Initialize handlers
        initializeHandlers();

        // Show first tab by default
        showIntegrityCheck();

        initWidget(rootPanel);
    }

    private void initializeHandlers() {
        integrityCheckMenuItem.addClickHandler(event -> showIntegrityCheck());
        clientManagementMenuItem.addClickHandler(event -> showClientManagement());
        externalSslMenuItem.addClickHandler(event -> showExternalSsl());
    }

    private void showIntegrityCheck() {
        setActiveMenuItem(integrityCheckMenuItem);
        contentPanel.setWidget(integrityCheckView);
    }

    private void showClientManagement() {
        setActiveMenuItem(clientManagementMenuItem);
        contentPanel.setWidget(clientManagementView);
    }

    private void showExternalSsl() {
        setActiveMenuItem(externalSslMenuItem);
        contentPanel.setWidget(externalSslView);
    }

    private void setActiveMenuItem(HTML menuItem) {
        // Remove active class from current active item
        if (currentActiveMenuItem != null) {
            currentActiveMenuItem.getElement().getStyle().clearBackgroundColor();
            currentActiveMenuItem.getElement().getStyle().clearColor();
            currentActiveMenuItem.getElement().getStyle().clearFontWeight();
        }

        // Add active class to new active item
        menuItem.getElement().getStyle().setProperty("backgroundColor", "#337ab7"); //$NON-NLS-1$ //$NON-NLS-2$
        menuItem.getElement().getStyle().setProperty("color", "white"); //$NON-NLS-1$ //$NON-NLS-2$
        menuItem.getElement().getStyle().setProperty("fontWeight", "bold"); //$NON-NLS-1$ //$NON-NLS-2$
        currentActiveMenuItem = menuItem;
    }
}
