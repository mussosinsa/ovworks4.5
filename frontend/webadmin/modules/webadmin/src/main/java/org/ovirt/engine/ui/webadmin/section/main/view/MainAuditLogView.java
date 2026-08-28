package org.ovirt.engine.ui.webadmin.section.main.view;

import org.ovirt.engine.ui.common.uicommon.model.MainModelProvider;
import org.ovirt.engine.ui.common.widget.table.SimpleActionTable;
import org.ovirt.engine.ui.uicommonweb.models.AuditLogListModel;
import org.ovirt.engine.ui.webadmin.gin.ClientGinjectorProvider;
import org.ovirt.engine.ui.webadmin.section.main.presenter.MainAuditLogPresenter;
import org.ovirt.engine.ui.webadmin.section.main.view.popup.security.AuditLogProtectionTabView;
import org.ovirt.engine.ui.webadmin.section.main.view.popup.security.AvailabilityTabView;

import com.google.gwt.core.client.Scheduler;
import com.google.gwt.user.client.ui.FlowPanel;
import com.google.gwt.user.client.ui.HTML;
import com.google.gwt.user.client.ui.SimplePanel;
import com.google.inject.Inject;

public class MainAuditLogView extends AbstractMainWithDetailsTableView<Object, AuditLogListModel>
        implements MainAuditLogPresenter.ViewDef {

    private final AuditLogProtectionTabView auditLogProtectionTabView;
    private final AvailabilityTabView availabilityTabView;

    private SimplePanel contentPanel;
    private HTML auditLogProtectionMenuItem;
    private HTML availabilityMenuItem;
    private HTML currentActiveMenuItem;
    private FlowPanel rootPanel;

    @Inject
    public MainAuditLogView(MainModelProvider<Object, AuditLogListModel> modelProvider,
            AuditLogProtectionTabView auditLogProtectionTabView,
            AvailabilityTabView availabilityTabView) {
        super(modelProvider);

        this.auditLogProtectionTabView = auditLogProtectionTabView;
        this.availabilityTabView = availabilityTabView;

        // Hide the default table to show the custom layout.
        getTable().setVisible(false);

        // Create main container
        FlowPanel mainContainer = new FlowPanel();
        mainContainer.getElement().getStyle().setProperty("width", "100%"); //$NON-NLS-1$ //$NON-NLS-2$
        mainContainer.getElement().getStyle().setProperty("minHeight", "600px"); //$NON-NLS-1$ //$NON-NLS-2$
        mainContainer.getElement().getStyle().setProperty("backgroundColor", "#ffffff"); //$NON-NLS-1$ //$NON-NLS-2$

        // Create tab bar
        FlowPanel tabBar = new FlowPanel();
        tabBar.getElement().getStyle().setProperty("padding", "10px 10px 0 10px"); //$NON-NLS-1$ //$NON-NLS-2$
        tabBar.getElement().getStyle().setProperty("borderBottom", "2px solid #1f6b8a"); //$NON-NLS-1$ //$NON-NLS-2$
        tabBar.getElement().getStyle().setProperty("backgroundColor", "#ffffff"); //$NON-NLS-1$ //$NON-NLS-2$

        // Create tab items
        auditLogProtectionMenuItem = new HTML("감사기록보호"); //$NON-NLS-1$
        auditLogProtectionMenuItem.getElement().getStyle().setProperty("display", "inline-block"); //$NON-NLS-1$ //$NON-NLS-2$
        auditLogProtectionMenuItem.getElement().getStyle().setProperty("padding", "6px 16px"); //$NON-NLS-1$ //$NON-NLS-2$
        auditLogProtectionMenuItem.getElement().getStyle().setProperty("marginRight", "10px"); //$NON-NLS-1$ //$NON-NLS-2$
        auditLogProtectionMenuItem.getElement().getStyle().setProperty("borderRadius", "6px"); //$NON-NLS-1$ //$NON-NLS-2$
        auditLogProtectionMenuItem.getElement().getStyle().setProperty("cursor", "pointer"); //$NON-NLS-1$ //$NON-NLS-2$
        tabBar.add(auditLogProtectionMenuItem);

        availabilityMenuItem = new HTML("가용성 확보"); //$NON-NLS-1$
        availabilityMenuItem.getElement().getStyle().setProperty("display", "inline-block"); //$NON-NLS-1$ //$NON-NLS-2$
        availabilityMenuItem.getElement().getStyle().setProperty("padding", "6px 16px"); //$NON-NLS-1$ //$NON-NLS-2$
        availabilityMenuItem.getElement().getStyle().setProperty("borderRadius", "6px"); //$NON-NLS-1$ //$NON-NLS-2$
        availabilityMenuItem.getElement().getStyle().setProperty("cursor", "pointer"); //$NON-NLS-1$ //$NON-NLS-2$
        tabBar.add(availabilityMenuItem);

        mainContainer.add(tabBar);
        setActiveMenuItem(auditLogProtectionMenuItem);

        // Create content panel
        contentPanel = new SimplePanel();
        contentPanel.getElement().getStyle().setProperty("backgroundColor", "#ffffff"); //$NON-NLS-1$ //$NON-NLS-2$
        contentPanel.getElement().getStyle().setProperty("overflowY", "auto"); //$NON-NLS-1$ //$NON-NLS-2$

        // Add content panel to main container
        mainContainer.add(contentPanel);
        if (auditLogProtectionTabView != null) {
            contentPanel.setWidget(auditLogProtectionTabView);
        }

        // Compose a root panel with the hidden table and the custom layout.
        rootPanel = new FlowPanel();
        rootPanel.add(getTable());
        rootPanel.add(mainContainer);

        // Make sure mainContainer is visible even though table is hidden
        mainContainer.setVisible(true);

        // Initialize handlers
        initializeHandlers();

        // Show first tab by default once the widget is attached.
        Scheduler.get().scheduleDeferred(() -> {
            if (rootPanel == null || !rootPanel.isAttached()) {
                return;
            }
            showAuditLogProtection();
        });

        initWidget(rootPanel);
    }

    @Override
    protected SimpleActionTable<Void, Object> createActionTable() {
        return new SimpleActionTable<Void, Object>(getModelProvider(), getTableResources(),
                ClientGinjectorProvider.getEventBus(), ClientGinjectorProvider.getClientStorage()) {
            {
                showRefreshButton();
                showItemsCount();
                enableHeaderContextMenu();
            }
        };
    }

    private void initializeHandlers() {
        auditLogProtectionMenuItem.addClickHandler(event -> showAuditLogProtection());
        availabilityMenuItem.addClickHandler(event -> showAvailability());
    }

    private void showAuditLogProtection() {
        setActiveMenuItem(auditLogProtectionMenuItem);
        if (contentPanel != null && auditLogProtectionTabView != null) {
            contentPanel.setWidget(auditLogProtectionTabView);
        }
    }

    private void showAvailability() {
        setActiveMenuItem(availabilityMenuItem);
        if (contentPanel != null && availabilityTabView != null) {
            contentPanel.setWidget(availabilityTabView);
        }
    }

    private void setActiveMenuItem(HTML menuItem) {
        if (menuItem == null) {
            return;
        }
        styleTab(auditLogProtectionMenuItem, menuItem == auditLogProtectionMenuItem);
        styleTab(availabilityMenuItem, menuItem == availabilityMenuItem);
        currentActiveMenuItem = menuItem;
    }

    private void styleTab(HTML tab, boolean isActive) {
        if (tab == null) {
            return;
        }
        tab.getElement().getStyle().setProperty("border", "1px solid #1f6b8a"); //$NON-NLS-1$ //$NON-NLS-2$
        tab.getElement().getStyle().setProperty("color", isActive ? "#ffffff" : "#1f6b8a"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        tab.getElement().getStyle().setProperty("backgroundColor", isActive ? "#1f6b8a" : "#f5f5f5"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        tab.getElement().getStyle().setProperty("fontWeight", isActive ? "bold" : "normal"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    }
}
