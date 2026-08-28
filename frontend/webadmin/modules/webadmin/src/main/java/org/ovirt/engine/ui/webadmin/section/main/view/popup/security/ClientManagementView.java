package org.ovirt.engine.ui.webadmin.section.main.view.popup.security;

import org.gwtbootstrap3.client.ui.Button;
import org.gwtbootstrap3.client.ui.TextBox;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.TerminalAuthParameters;
import org.ovirt.engine.core.common.action.TerminalIpAuthParameters;
import org.ovirt.engine.core.common.queries.QueryParametersBase;
import org.ovirt.engine.core.common.queries.QueryReturnValue;
import org.ovirt.engine.core.common.queries.QueryType;
import org.ovirt.engine.ui.frontend.AsyncQuery;
import org.ovirt.engine.ui.frontend.Frontend;
import org.ovirt.engine.ui.uicompat.FrontendActionAsyncResult;
import org.ovirt.engine.ui.webadmin.ApplicationConstants;
import org.ovirt.engine.ui.webadmin.gin.AssetProvider;

import com.google.gwt.core.client.GWT;
import com.google.gwt.event.dom.client.ClickEvent;
import com.google.gwt.event.dom.client.ClickHandler;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.user.client.Window;
import com.google.gwt.user.client.ui.Composite;
import com.google.gwt.user.client.ui.ListBox;
import com.google.gwt.user.client.ui.Widget;

public class ClientManagementView extends Composite {
    interface ViewUiBinder extends UiBinder<Widget, ClientManagementView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    private static final ApplicationConstants constants = AssetProvider.getConstants();

    @UiField
    TextBox terminalAuthInput;

    @UiField
    Button terminalAuthButton;

    @UiField
    TextBox terminalIpInput;

    @UiField
    ListBox terminalIpList;

    @UiField
    Button terminalIpAddButton;

    @UiField
    Button terminalIpButton;

    @UiField
    Button terminalIpDeleteButton;

    public ClientManagementView() {
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        initializeHandlers();
        loadTerminalAuthSerialNumber();
        loadTerminalIpAuth();
    }

    private void initializeHandlers() {
        terminalAuthButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                String serialNum = terminalAuthInput.getText();
                if (serialNum == null || serialNum.trim().isEmpty()) {
                    Window.alert("단말기 일련번호를 입력하세요."); //$NON-NLS-1$
                    return;
                }
                applyTerminalAuth(serialNum.trim());
            }
        });

        terminalIpList.addChangeHandler(event -> {
            int selected = terminalIpList.getSelectedIndex();
            terminalIpInput.setText(selected < 0 ? "" : terminalIpList.getItemText(selected)); //$NON-NLS-1$
        });
        terminalIpAddButton.addClickHandler(event -> addTerminalIp());
        terminalIpButton.addClickHandler(event -> updateSelectedTerminalIp());
        terminalIpDeleteButton.addClickHandler(event -> deleteSelectedTerminalIp());
    }

    private boolean isValidSingleIpInput(String value) {
        if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            return false;
        }
        int separator = value.indexOf('/');
        if (separator < 0) {
            return isValidIpv4Address(value);
        }
        if (separator == 0 || separator != value.lastIndexOf('/') || separator == value.length() - 1
                || !isValidIpv4Address(value.substring(0, separator))) {
            return false;
        }
        String prefix = value.substring(separator + 1);
        int prefixLength = parseCidrPrefix(prefix);
        return prefixLength >= 0 && prefixLength <= 32 && Integer.toString(prefixLength).equals(prefix);
    }

    private int parseCidrPrefix(String prefix) {
        if (prefix.isEmpty()) {
            return -1;
        }
        int result = 0;
        for (int index = 0; index < prefix.length(); index++) {
            char character = prefix.charAt(index);
            if (character < '0' || character > '9') {
                return -1;
            }
            result = result * 10 + character - '0';
        }
        return result;
    }

    private String validatedTerminalIp() {
        String value = terminalIpInput.getText() == null ? "" : terminalIpInput.getText().trim(); //$NON-NLS-1$
        if (value.isEmpty()) {
            Window.alert("IP 주소를 입력하세요."); //$NON-NLS-1$
            return null;
        }
        if (!isValidSingleIpInput(value)) {
            Window.alert("하나의 IPv4 주소 또는 IPv4 CIDR 대역만 입력할 수 있습니다."); //$NON-NLS-1$
            return null;
        }
        return value;
    }

    private void addTerminalIp() {
        String value = validatedTerminalIp();
        if (value == null || findTerminalIp(value, -1)) {
            return;
        }
        terminalIpList.addItem(value);
        resizeTerminalIpList();
        terminalIpList.setSelectedIndex(terminalIpList.getItemCount() - 1);
        applyTerminalIpAuth(terminalIpListValue());
    }

    private void updateSelectedTerminalIp() {
        int selected = terminalIpList.getSelectedIndex();
        if (selected < 0) {
            Window.alert("수정할 IP를 목록에서 선택하세요."); //$NON-NLS-1$
            return;
        }
        String value = validatedTerminalIp();
        if (value == null || findTerminalIp(value, selected)) {
            return;
        }
        terminalIpList.setItemText(selected, value);
        applyTerminalIpAuth(terminalIpListValue());
    }

    private void deleteSelectedTerminalIp() {
        int selected = terminalIpList.getSelectedIndex();
        if (selected < 0) {
            Window.alert("삭제할 IP를 목록에서 선택하세요."); //$NON-NLS-1$
            return;
        }
        terminalIpList.removeItem(selected);
        resizeTerminalIpList();
        terminalIpInput.setText(""); //$NON-NLS-1$
        applyTerminalIpAuth(terminalIpListValue());
    }

    private boolean findTerminalIp(String value, int ignoredIndex) {
        for (int index = 0; index < terminalIpList.getItemCount(); index++) {
            if (index != ignoredIndex && value.equals(terminalIpList.getItemText(index))) {
                Window.alert("이미 등록된 IP 주소입니다."); //$NON-NLS-1$
                return true;
            }
        }
        return false;
    }

    private String terminalIpListValue() {
        StringBuilder value = new StringBuilder();
        for (int index = 0; index < terminalIpList.getItemCount(); index++) {
            if (value.length() > 0) {
                value.append('\n');
            }
            value.append(terminalIpList.getItemText(index));
        }
        return value.toString();
    }

    private boolean isValidIpv4Address(String value) {
        String[] octets = value.split("\\.", -1); //$NON-NLS-1$
        if (octets.length != 4) {
            return false;
        }
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3) {
                return false;
            }
            int number = 0;
            for (int index = 0; index < octet.length(); index++) {
                char character = octet.charAt(index);
                if (character < '0' || character > '9') {
                    return false;
                }
                number = number * 10 + character - '0';
            }
            if (number > 255) {
                return false;
            }
        }
        return true;
    }

    private void applyTerminalAuth(String serialNum) {
        TerminalAuthParameters params = new TerminalAuthParameters();
        params.setSerialNumber(serialNum);

        Frontend.getInstance().runAction(
            ActionType.SetTerminalAuth,
            params,
            result -> handleActionResult(result, "단말기 인증이 적용되었습니다.") //$NON-NLS-1$
        );
    }

    private void loadTerminalAuthSerialNumber() {
        Frontend.getInstance().runQuery(
                QueryType.GetTerminalAuthSerial,
                new QueryParametersBase(),
                new AsyncQuery<QueryReturnValue>(returnValue -> {
                    if (returnValue != null && returnValue.getReturnValue() instanceof String) {
                        terminalAuthInput.setText((String) returnValue.getReturnValue());
                    }
                }));
    }

    private void loadTerminalIpAuth() {
        Frontend.getInstance().runQuery(
                QueryType.GetTerminalIpAuth,
                new QueryParametersBase(),
                new AsyncQuery<QueryReturnValue>(returnValue -> {
                    if (returnValue != null && returnValue.getReturnValue() instanceof String) {
                        String requireIp = (String) returnValue.getReturnValue();
                        terminalIpList.clear();
                        for (String ip : requireIp.split("\\r?\\n")) { //$NON-NLS-1$
                            if (!ip.trim().isEmpty()) {
                                terminalIpList.addItem(ip.trim());
                            }
                        }
                        resizeTerminalIpList();
                        if (terminalIpList.getItemCount() > 0) {
                            terminalIpList.setSelectedIndex(0);
                            terminalIpInput.setText(terminalIpList.getItemText(0));
                        }
                    }
                }));
    }

    private void resizeTerminalIpList() {
        terminalIpList.setVisibleItemCount(Math.max(1, Math.min(terminalIpList.getItemCount(), 4)));
    }

    private void applyTerminalIpAuth(String ipAddress) {
        TerminalIpAuthParameters params = new TerminalIpAuthParameters();
        params.setIpAddress(ipAddress);

        Frontend.getInstance().runAction(
            ActionType.SetTerminalIpAuth,
            params,
            result -> {
                handleActionResult(result, "단말기 IP 인증이 적용되었습니다."); //$NON-NLS-1$
                loadTerminalIpAuth();
            }
        );
    }

    private void handleActionResult(FrontendActionAsyncResult result, String successMessage) {
        if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
            Window.alert(successMessage);
        } else {
            String errorMsg = "작업 실행에 실패했습니다."; //$NON-NLS-1$
            if (result != null && result.getReturnValue() != null &&
                result.getReturnValue().getFault() != null) {
                errorMsg += "\n" + result.getReturnValue().getFault().getMessage(); //$NON-NLS-1$
            }
            Window.alert(errorMsg);
        }
    }
}
