package org.ovirt.engine.ui.uicommonweb.models;

import java.util.ArrayList;
import java.util.List;

import org.ovirt.engine.ui.uicommonweb.help.HelpTag;

/**
 * Model for Audit Log Management main tab.
 */
public class AuditLogListModel extends ListWithDetailsModel {

    public AuditLogListModel() {
        super();
        setTitle("Audit Log Management"); //$NON-NLS-1$
        setHelpTag(HelpTag.audit_log);
        setHashName("audit_log"); //$NON-NLS-1$
        setDefaultSearchString(""); //$NON-NLS-1$
        setSearchString(""); //$NON-NLS-1$

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
        return "AuditLogListModel"; //$NON-NLS-1$
    }
}
