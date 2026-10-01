package org.ovirt.engine.ui.webadmin.section.main.view.popup;

import java.util.ArrayList;
import java.util.List;

import org.ovirt.engine.core.common.action.CommandBlacklist;
import org.ovirt.engine.ui.common.view.AbstractPopupView;
import org.ovirt.engine.ui.common.widget.dialog.PopupNativeKeyPressHandler;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogButton;
import org.ovirt.engine.ui.common.widget.dialog.SimpleDialogPanel;
import org.ovirt.engine.ui.webadmin.ApplicationConstants;
import org.ovirt.engine.ui.webadmin.ApplicationMessages;
import org.ovirt.engine.ui.webadmin.gin.AssetProvider;
import org.ovirt.engine.ui.webadmin.section.main.presenter.popup.VmSecurityControlPopupPresenterWidget;

import com.google.gwt.core.client.GWT;
import com.google.gwt.dom.client.Style;
import com.google.gwt.event.dom.client.HasClickHandlers;
import com.google.gwt.event.dom.client.KeyCodes;
import com.google.gwt.event.shared.EventBus;
import com.google.gwt.event.shared.HandlerRegistration;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.user.client.ui.Anchor;
import com.google.gwt.user.client.ui.Button;
import com.google.gwt.user.client.ui.FlexTable;
import com.google.gwt.user.client.ui.FlowPanel;
import com.google.gwt.user.client.ui.HTMLPanel;
import com.google.gwt.user.client.ui.Label;
import com.google.gwt.user.client.ui.ListBox;
import com.google.gwt.user.client.ui.RadioButton;
import com.google.gwt.user.client.ui.TextBox;
import com.google.inject.Inject;

public class VmSecurityControlPopupView extends AbstractPopupView<SimpleDialogPanel>
        implements VmSecurityControlPopupPresenterWidget.ViewDef {

    interface ViewUiBinder extends UiBinder<SimpleDialogPanel, VmSecurityControlPopupView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    private static final ApplicationConstants constants = AssetProvider.getConstants();

    private static final ApplicationMessages messages = AssetProvider.getMessages();

    /** How many blacklist entries one page of the table shows. */
    static final int BLACKLIST_PAGE_SIZE = 10;

    /** The events last fetched from the guest. The filter box narrows what is drawn from them. */
    private final List<String[]> guestEvents = new ArrayList<>();

    /**
     * The blacklist as it is being edited: program and description. Nothing here reaches the
     * guest until it is saved, which is why a change is marked as unsaved until then.
     */
    private final List<String[]> blacklist = new ArrayList<>();

    private int blacklistPage;

    @UiField
    SimpleDialogButton closeButton;

    @UiField
    TextBox vmId;

    @UiField
    TextBox dnsServer;

    @UiField
    TextBox blacklistCommand;

    @UiField
    TextBox blacklistDescription;

    @UiField
    Button addBlacklistButton;

    @UiField
    Label blacklistInputMessage;

    @UiField
    Label blacklistCount;

    @UiField
    Button reloadBlacklistButton;

    @UiField
    FlexTable blacklistTable;

    @UiField
    Label blacklistRange;

    @UiField
    FlowPanel blacklistPager;

    @UiField
    Button cancelBlacklistButton;

    @UiField
    Button saveBlacklistButton;

    @UiField
    Label blacklistResult;

    @UiField
    ListBox networkAdapter;

    @UiField
    Button refreshNetworkAdaptersButton;

    @UiField
    RadioButton disableNetworkRadioButton;

    @UiField
    RadioButton enableDhcpRadioButton;

    @UiField
    RadioButton enableStaticRadioButton;

    @UiField
    HTMLPanel ipDetailsPanel;

    @UiField
    TextBox ipAddress;

    @UiField
    TextBox subnetMask;

    @UiField
    TextBox gateway;

    @UiField
    Button applyNetworkSettingsButton;

    @UiField
    Label networkSettingsResult;

    @UiField
    RadioButton blockFileSharingRadioButton;

    @UiField
    Button applyFileSharingSettingsButton;

    @UiField
    Label fileSharingSettingsResult;

    @UiField
    RadioButton blockManagementCommandsRadioButton;

    @UiField
    Button applyManagementBlockButton;

    @UiField
    Label managementBlockResult;

    @UiField
    RadioButton blockUserPathRadioButton;

    @UiField
    Button applyUserPathBlockButton;

    @UiField
    Label userPathBlockResult;

    @UiField
    TextBox eventFilter;

    @UiField
    Button refreshGuestEventsButton;

    @UiField
    FlexTable guestEventTable;

    @UiField
    Label guestEventsMessage;

    @Inject
    public VmSecurityControlPopupView(EventBus eventBus) {
        super(eventBus);
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        disableNetworkRadioButton.addValueChangeHandler(event -> {
            if (event.getValue()) {
                showIpDetails(false);
            }
        });
        enableDhcpRadioButton.addValueChangeHandler(event -> {
            if (event.getValue()) {
                showIpDetails(false);
            }
        });
        enableStaticRadioButton.addValueChangeHandler(event -> {
            if (event.getValue()) {
                showIpDetails(true);
            }
        });
        showIpDetails(enableStaticRadioButton.getValue());
        eventFilter.getElement().setAttribute("placeholder", constants.vmSecurityFilter()); //$NON-NLS-1$
        eventFilter.addKeyUpHandler(event -> drawGuestEvents());
        drawGuestEvents();
        blacklistCommand.getElement().setAttribute("placeholder", constants.vmSecurityBlacklistPlaceholder()); //$NON-NLS-1$
        blacklistDescription.getElement().setAttribute("placeholder", //$NON-NLS-1$
                constants.vmSecurityBlacklistNotePlaceholder());
        blacklistDescription.setMaxLength(CommandBlacklist.MAX_DESCRIPTION_LENGTH);
        addBlacklistButton.addClickHandler(event -> addBlacklistEntry());
        blacklistCommand.addKeyDownHandler(event -> {
            if (event.getNativeKeyCode() == KeyCodes.KEY_ENTER) {
                addBlacklistEntry();
            }
        });
        blacklistDescription.addKeyDownHandler(event -> {
            if (event.getNativeKeyCode() == KeyCodes.KEY_ENTER) {
                addBlacklistEntry();
            }
        });
        drawBlacklist();
    }

    /**
     * Adds what was typed to the list, as the program it refers to.
     *
     * <p>Checked by the same rules the engine applies, so that an entry the engine would refuse is
     * refused here, where it can still be corrected.</p>
     */
    private void addBlacklistEntry() {
        String description = blacklistDescription.getText().trim();
        CommandBlacklist.Problem problem = CommandBlacklist.check(blacklistCommand.getText(), description);
        if (problem != null) {
            blacklistInputMessage.setText(describe(problem));
            return;
        }
        String program = CommandBlacklist.normalize(blacklistCommand.getText());
        if (contains(program)) {
            blacklistInputMessage.setText(constants.vmSecurityBlacklistDuplicate());
            return;
        }
        if (blacklist.size() >= CommandBlacklist.MAX_ENTRIES) {
            blacklistInputMessage.setText(constants.vmSecurityBlacklistFull());
            return;
        }
        blacklist.add(new String[] { program, description });
        blacklistCommand.setText(""); //$NON-NLS-1$
        blacklistDescription.setText(""); //$NON-NLS-1$
        blacklistInputMessage.setText(""); //$NON-NLS-1$
        blacklistPage = pageCount() - 1;
        markBlacklistChanged();
        blacklistCommand.setFocus(true);
    }

    private boolean contains(String program) {
        for (String[] entry : blacklist) {
            if (entry[0].equals(program)) {
                return true;
            }
        }
        return false;
    }

    private static String describe(CommandBlacklist.Problem problem) {
        switch (problem) {
        case PROTECTED:
            return constants.vmSecurityBlacklistProtected();
        case INVALID_DESCRIPTION:
            return constants.vmSecurityBlacklistInvalidNote();
        default:
            return constants.vmSecurityBlacklistInvalid();
        }
    }

    private void removeBlacklistEntry(int index) {
        blacklist.remove(index);
        blacklistPage = Math.min(blacklistPage, pageCount() - 1);
        markBlacklistChanged();
    }

    private void markBlacklistChanged() {
        blacklistResult.setText(constants.vmSecurityBlacklistUnsaved());
        drawBlacklist();
    }

    private int pageCount() {
        return Math.max(1, (blacklist.size() + BLACKLIST_PAGE_SIZE - 1) / BLACKLIST_PAGE_SIZE);
    }

    /** Redraws the table, the count above it and the pages below it from the list held. */
    private void drawBlacklist() {
        blacklistCount.setText(messages.vmSecurityBlacklistCount(blacklist.size()));
        blacklistTable.removeAllRows();
        blacklistTable.setText(0, 0, constants.vmSecurityBlacklistCommand());
        blacklistTable.setText(0, 1, constants.vmSecurityBlacklistNote());
        blacklistTable.setText(0, 2, constants.vmSecurityBlacklistAction());
        blacklistTable.getRowFormatter().setStyleName(0, "active"); //$NON-NLS-1$
        blacklistTable.getColumnFormatter().setWidth(0, "35%"); //$NON-NLS-1$
        blacklistTable.getColumnFormatter().setWidth(2, "90px"); //$NON-NLS-1$
        int first = blacklistPage * BLACKLIST_PAGE_SIZE;
        int last = Math.min(first + BLACKLIST_PAGE_SIZE, blacklist.size());
        for (int index = first; index < last; index++) {
            int row = index - first + 1;
            String[] entry = blacklist.get(index);
            // setText escapes, which matters for what was read back from the guest.
            blacklistTable.setText(row, 0, entry[0]);
            blacklistTable.setText(row, 1, entry.length > 1 ? entry[1] : ""); //$NON-NLS-1$
            final int target = index;
            Anchor delete = new Anchor("\u2716 " + constants.vmSecurityBlacklistDelete()); //$NON-NLS-1$
            delete.getElement().getStyle().setColor("#c9190b"); //$NON-NLS-1$
            delete.getElement().getStyle().setCursor(Style.Cursor.POINTER);
            delete.addClickHandler(event -> removeBlacklistEntry(target));
            blacklistTable.setWidget(row, 2, delete);
        }
        if (blacklist.isEmpty()) {
            blacklistTable.setText(1, 0, constants.vmSecurityBlacklistEmpty());
            blacklistTable.getFlexCellFormatter().setColSpan(1, 0, 3);
        }
        blacklistRange.setText(blacklist.isEmpty() ? "" //$NON-NLS-1$
                : messages.vmSecurityBlacklistRange(first + 1, last, blacklist.size()));
        drawBlacklistPager();
    }

    /** Prev, the pages around the current one, and Next - as in "[Prev] 1 [2] 3 ... [Next]". */
    private void drawBlacklistPager() {
        blacklistPager.clear();
        int pages = pageCount();
        blacklistPager.add(pageLink("[" + constants.vmSecurityBlacklistPrev() + "]", //$NON-NLS-1$ //$NON-NLS-2$
                blacklistPage - 1, blacklistPage > 0));
        int from = Math.max(0, Math.min(blacklistPage - 2, pages - 5));
        int to = Math.min(pages, from + 5);
        for (int page = from; page < to; page++) {
            Anchor link = pageLink(Integer.toString(page + 1), page, page != blacklistPage);
            if (page == blacklistPage) {
                link.getElement().getStyle().setProperty("fontWeight", "bold"); //$NON-NLS-1$ //$NON-NLS-2$
                link.getElement().getStyle().setProperty("border", "1px solid #ccc"); //$NON-NLS-1$ //$NON-NLS-2$
                link.getElement().getStyle().setProperty("padding", "0 5px"); //$NON-NLS-1$ //$NON-NLS-2$
            }
            blacklistPager.add(link);
        }
        if (to < pages) {
            blacklistPager.add(pageLink("...", pages - 1, true)); //$NON-NLS-1$
        }
        blacklistPager.add(pageLink("[" + constants.vmSecurityBlacklistNext() + "]", //$NON-NLS-1$ //$NON-NLS-2$
                blacklistPage + 1, blacklistPage < pages - 1));
    }

    private Anchor pageLink(String text, int page, boolean enabled) {
        Anchor link = new Anchor(text);
        if (enabled) {
            link.addClickHandler(event -> {
                blacklistPage = page;
                drawBlacklist();
            });
        } else {
            link.getElement().getStyle().setColor("#aaa"); //$NON-NLS-1$
            link.getElement().getStyle().setCursor(Style.Cursor.DEFAULT);
        }
        return link;
    }

    /** Redraws the table from the events held, keeping only the ones the filter matches. */
    private void drawGuestEvents() {
        guestEventTable.removeAllRows();
        guestEventTable.setText(0, 0, constants.vmSecurityTime());
        guestEventTable.setText(0, 1, constants.vmSecurityEventType());
        guestEventTable.setText(0, 2, constants.vmSecurityStatus());
        guestEventTable.setText(0, 3, constants.vmSecurityMessage());
        guestEventTable.getRowFormatter().setStyleName(0, "active"); //$NON-NLS-1$

        String filter = eventFilter.getText().trim().toLowerCase();
        int row = 1;
        for (String[] event : guestEvents) {
            if (!matches(event, filter)) {
                continue;
            }
            for (int column = 0; column < 4; column++) {
                // setText escapes, which matters because the guest writes these messages.
                guestEventTable.setText(row, column, column < event.length ? event[column] : ""); //$NON-NLS-1$
            }
            row++;
        }
        if (row == 1 && !guestEvents.isEmpty()) {
            guestEventsMessage.setText(constants.vmSecurityNoEvents());
        }
    }

    private static boolean matches(String[] event, String filter) {
        if (filter.isEmpty()) {
            return true;
        }
        for (String field : event) {
            if (field.toLowerCase().contains(filter)) {
                return true;
            }
        }
        return false;
    }

    /** The addresses are asked for only when the adapter is being given one of its own. */
    private void showIpDetails(boolean staticAddress) {
        ipDetailsPanel.setVisible(staticAddress);
    }

    @Override
    public HasClickHandlers getCloseButton() {
        return closeButton;
    }

    @Override
    public HasClickHandlers getSaveBlacklistButton() {
        return saveBlacklistButton;
    }

    @Override
    public HasClickHandlers getCancelBlacklistButton() {
        return cancelBlacklistButton;
    }

    @Override
    public HasClickHandlers getReloadBlacklistButton() {
        return reloadBlacklistButton;
    }

    @Override
    public void setBlacklist(List<String[]> entries) {
        blacklist.clear();
        for (String[] entry : entries) {
            // Once each: a guest blocked by the old command prompt menu and then by the list can
            // hold a rule for cmd.exe under each mark, and the list may name a program only once.
            if (!contains(entry[0])) {
                blacklist.add(entry);
            }
        }
        blacklistPage = 0;
        blacklistInputMessage.setText(""); //$NON-NLS-1$
        drawBlacklist();
    }

    @Override
    public List<String[]> getBlacklist() {
        return new ArrayList<>(blacklist);
    }

    @Override
    public void setBlacklistResult(String result) {
        blacklistResult.setText(result);
    }

    @Override
    public void setBlacklistBusy(boolean busy) {
        saveBlacklistButton.setEnabled(!busy);
        cancelBlacklistButton.setEnabled(!busy);
        reloadBlacklistButton.setEnabled(!busy);
    }

    @Override
    public HasClickHandlers getApplyNetworkSettingsButton() {
        return applyNetworkSettingsButton;
    }

    @Override
    public HasClickHandlers getRefreshNetworkAdaptersButton() {
        return refreshNetworkAdaptersButton;
    }

    @Override
    public void clearNetworkAdapters() {
        networkAdapter.clear();
    }

    @Override
    public void addNetworkAdapter(String label, String macAddress) {
        networkAdapter.addItem(label, macAddress);
    }

    @Override
    public String getSelectedMacAddress() {
        int selected = networkAdapter.getSelectedIndex();
        return selected < 0 ? "" : networkAdapter.getValue(selected); //$NON-NLS-1$
    }

    @Override
    public boolean isNetworkEnabled() {
        return enableDhcpRadioButton.getValue() || enableStaticRadioButton.getValue();
    }

    @Override
    public boolean isDhcp() {
        return enableDhcpRadioButton.getValue();
    }

    @Override
    public String getDnsServer() {
        return dnsServer.getText().trim();
    }

    @Override
    public String getIpAddress() {
        return ipAddress.getText().trim();
    }

    @Override
    public String getSubnetMask() {
        return subnetMask.getText().trim();
    }

    @Override
    public String getGateway() {
        return gateway.getText().trim();
    }

    @Override
    public void setNetworkSettingsResult(String result) {
        networkSettingsResult.setText(result);
    }

    @Override
    public HasClickHandlers getApplyFileSharingSettingsButton() {
        return applyFileSharingSettingsButton;
    }

    @Override
    public boolean isFileSharingBlocked() {
        return blockFileSharingRadioButton.getValue();
    }

    @Override
    public void setFileSharingSettingsResult(String result) {
        fileSharingSettingsResult.setText(result);
    }

    @Override
    public HasClickHandlers getApplyManagementBlockButton() {
        return applyManagementBlockButton;
    }

    @Override
    public boolean isManagementCommandsBlocked() {
        return blockManagementCommandsRadioButton.getValue();
    }

    @Override
    public void setManagementBlockResult(String result) {
        managementBlockResult.setText(result);
    }

    @Override
    public HasClickHandlers getApplyUserPathBlockButton() {
        return applyUserPathBlockButton;
    }

    @Override
    public boolean isUserPathExecutionBlocked() {
        return blockUserPathRadioButton.getValue();
    }

    @Override
    public void setUserPathBlockResult(String result) {
        userPathBlockResult.setText(result);
    }

    @Override
    public HasClickHandlers getRefreshGuestEventsButton() {
        return refreshGuestEventsButton;
    }

    @Override
    public void setGuestEvents(List<String[]> events) {
        guestEvents.clear();
        guestEvents.addAll(events);
        guestEventsMessage.setText(events.isEmpty() ? constants.vmSecurityNoEvents() : ""); //$NON-NLS-1$
        drawGuestEvents();
    }

    @Override
    public void setGuestEventsMessage(String message) {
        guestEventsMessage.setText(message);
    }

    @Override
    public String getVmId() {
        return vmId.getText();
    }


    @Override
    public void setVmId(String value) {
        vmId.setText(value);
    }

    @Override
    public HasClickHandlers getCloseIconButton() {
        return asWidget().getCloseIconButton();
    }

    @Override
    public HandlerRegistration setPopupKeyPressHandler(PopupNativeKeyPressHandler handler) {
        return asWidget().setKeyPressHandler(handler);
    }
}
