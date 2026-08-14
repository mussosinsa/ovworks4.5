package org.ovirt.engine.ui.webadmin.section.main.view.popup.security;

import org.gwtbootstrap3.client.ui.Button;
import org.gwtbootstrap3.client.ui.TextArea;
import org.gwtbootstrap3.client.ui.TextBox;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.TerminalAuthParameters;
import org.ovirt.engine.core.common.action.TerminalIpAuthParameters;
import org.ovirt.engine.core.common.utils.Ipv4AddressUtils;
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
    TextArea terminalIpInput;

    @UiField
    Button terminalIpButton;

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

        terminalIpButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                String ipAddress = terminalIpInput.getText();
                if (ipAddress == null || ipAddress.trim().isEmpty()) {
                    Window.alert("IP 주소를 입력하세요."); //$NON-NLS-1$
                    return;
                }
                if (!isValidSingleIpInput(ipAddress.trim())) {
                    Window.alert("단말기 IP 인증은 CIDR/대역 입력 없이 단일 IPv4 주소만 허용됩니다."); //$NON-NLS-1$
                    return;
                }
                applyTerminalIpAuth(ipAddress.trim());
            }
        });
    }

    private boolean isValidSingleIpInput(String value) {
        String[] lines = value.split("\\r?\\n"); //$NON-NLS-1$
        for (String line : lines) {
            String candidate = line.trim();
            if (candidate.isEmpty()) {
                continue;
            }
            if (!Ipv4AddressUtils.isValidAddress(candidate)) {
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
                        terminalIpInput.setText(requireIp);
                    }
                }));
    }

    private void applyTerminalIpAuth(String ipAddress) {
        TerminalIpAuthParameters params = new TerminalIpAuthParameters();
        params.setIpAddress(ipAddress);

        Frontend.getInstance().runAction(
            ActionType.SetTerminalIpAuth,
            params,
            result -> {
                handleActionResult(result, "단말기 IP 인증이 적용되었습니다."); //$NON-NLS-1$
                if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                    loadTerminalIpAuth();
                }
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
