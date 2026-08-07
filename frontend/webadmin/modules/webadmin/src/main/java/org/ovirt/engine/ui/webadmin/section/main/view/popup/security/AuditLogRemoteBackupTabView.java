package org.ovirt.engine.ui.webadmin.section.main.view.popup.security;

import java.util.Date;

import org.gwtbootstrap3.client.ui.Button;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.AuditLogBackupParameters;
import org.ovirt.engine.ui.frontend.Frontend;
import org.ovirt.engine.ui.uicompat.FrontendActionAsyncResult;

import com.google.gwt.core.client.GWT;
import com.google.gwt.event.dom.client.ClickHandler;
import com.google.gwt.i18n.client.DateTimeFormat;
import com.google.gwt.safehtml.shared.SafeHtmlUtils;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.user.client.ui.Composite;
import com.google.gwt.user.client.ui.HTML;
import com.google.gwt.user.client.ui.TextBox;
import com.google.gwt.user.client.ui.Widget;

public class AuditLogRemoteBackupTabView extends Composite {

    interface ViewUiBinder extends UiBinder<Widget, AuditLogRemoteBackupTabView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    @UiField
    Button remoteBackupButton;

    @UiField
    HTML remoteBackupResultLabel;

    @UiField
    TextBox remoteBackupAddressInput;

    public AuditLogRemoteBackupTabView() {
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        initializeHandlers();
    }

    private void initializeHandlers() {
        remoteBackupButton.addClickHandler((ClickHandler) event -> {
            String remoteAddress = remoteBackupAddressInput.getText().trim();
            if (remoteAddress.isEmpty()) {
                remoteBackupResultLabel.setText("원격 서버 주소를 입력해 주세요."); //$NON-NLS-1$
                return;
            }
            AuditLogBackupParameters parameters = new AuditLogBackupParameters();
            parameters.setRemoteAddress(remoteAddress);
            remoteBackupResultLabel.setText("처리 중..."); //$NON-NLS-1$
            Frontend.getInstance().runAction(ActionType.RemoteBackup, parameters, result -> {
                handleResult(result, buildSuccessMessage(remoteAddress), remoteBackupResultLabel);
            });
        });
    }

    private String buildSuccessMessage(String remoteAddress) {
        return "처리날짜 : " + currentTimestamp() + " - 정상저장\n" //$NON-NLS-1$ //$NON-NLS-2$
                + "원격 서버 주소: " + remoteAddress + "\n" //$NON-NLS-1$ //$NON-NLS-2$
                + "rsyslog 설정 검증·적용 및 서비스 재시작 완료"; //$NON-NLS-1$
    }

    private String currentTimestamp() {
        return DateTimeFormat.getFormat("yyyy-MM-dd HH:mm:ss").format(new Date()); //$NON-NLS-1$
    }

    private void handleResult(FrontendActionAsyncResult result, String successMessage, HTML target) {
        StringBuilder details = new StringBuilder();
        if (result != null && result.getReturnValue() != null) {
            if (result.getReturnValue().getSucceeded()) {
                details.append(successMessage);
                Object actionReturnValue = result.getReturnValue().getActionReturnValue();
                if (actionReturnValue instanceof String && !((String) actionReturnValue).isEmpty()) {
                    details.append("\n").append(actionReturnValue); //$NON-NLS-1$
                }
                target.setHTML(formatHtml(details.toString()));
                return;
            }
            if (result.getReturnValue().getExecuteFailedMessages() != null) {
                result.getReturnValue().getExecuteFailedMessages().forEach(msg -> {
                    details.append(msg).append("\n"); //$NON-NLS-1$
                });
            }
            Object actionReturnValue = result.getReturnValue().getActionReturnValue();
            if (actionReturnValue instanceof String && !((String) actionReturnValue).isEmpty()) {
                details.append(actionReturnValue);
            }
        }
        if (details.length() == 0) {
            details.append("원격 백업 실행 중 오류가 발생했습니다."); //$NON-NLS-1$
        }
        target.setHTML(formatHtml(details.toString().trim()));
    }

    private String formatHtml(String message) {
        return SafeHtmlUtils.fromString(message).asString().replace("\n", "<br/>"); //$NON-NLS-1$ //$NON-NLS-2$
    }
}
