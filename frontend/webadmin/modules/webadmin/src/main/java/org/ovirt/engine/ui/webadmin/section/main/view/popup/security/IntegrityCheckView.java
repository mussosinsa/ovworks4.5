package org.ovirt.engine.ui.webadmin.section.main.view.popup.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;

import org.gwtbootstrap3.client.ui.Button;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.action.ActionParametersBase;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.businessentities.AuditLog;
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
import com.google.gwt.i18n.client.DateTimeFormat;
import com.google.gwt.safehtml.shared.SafeHtmlUtils;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.user.client.Timer;
import com.google.gwt.user.client.ui.Composite;
import com.google.gwt.user.client.ui.HTML;
import com.google.gwt.user.client.ui.Label;
import com.google.gwt.user.client.ui.Widget;

public class IntegrityCheckView extends Composite {
    private static final int HISTORY_LIMIT = 10;
    private static final int HISTORY_REFRESH_ATTEMPTS = 5;
    private static final int HISTORY_REFRESH_DELAY_MILLIS = 1000;
    private static final DateTimeFormat HISTORY_TIME_FORMAT = DateTimeFormat.getFormat("yyyy-MM-dd HH:mm:ss"); //$NON-NLS-1$

    interface ViewUiBinder extends UiBinder<Widget, IntegrityCheckView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    private static final ApplicationConstants constants = AssetProvider.getConstants();

    @UiField
    Button securityAuditButton;

    @UiField
    Button integrityVerificationButton;

    @UiField
    Label securityAuditStatusLabel;

    @UiField
    Label integrityVerificationStatusLabel;

    @UiField
    HTML securityAuditErrorLabel;

    @UiField
    HTML integrityVerificationErrorLabel;

    @UiField
    HTML securityAuditHistoryLabel;

    @UiField
    HTML integrityVerificationHistoryLabel;

    public IntegrityCheckView() {
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        securityAuditHistoryLabel.setHTML(SafeHtmlUtils.fromString("실행 이력이 없습니다.").asString()); //$NON-NLS-1$
        integrityVerificationHistoryLabel.setHTML(SafeHtmlUtils.fromString("실행 이력이 없습니다.").asString()); //$NON-NLS-1$
        initializeHandlers();
        loadVerificationHistory();
    }

    private void initializeHandlers() {
        securityAuditButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                setRunningState(
                        securityAuditButton,
                        securityAuditStatusLabel,
                        securityAuditErrorLabel
                );
                executeSecurityAudit();
            }
        });

        integrityVerificationButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                setRunningState(
                        integrityVerificationButton,
                        integrityVerificationStatusLabel,
                        integrityVerificationErrorLabel
                );
                executeIntegrityVerification();
            }
        });
    }

    private void setRunningState(Button button, Label statusLabel, HTML errorLabel) {
        button.setEnabled(false);
        statusLabel.setText(constants.statusRunning());
        resetStatusStyles(statusLabel);
        statusLabel.addStyleName("text-warning"); //$NON-NLS-1$
        errorLabel.setHTML(""); //$NON-NLS-1$
        errorLabel.setVisible(false);
    }

    private void setNormalState(Button button, Label statusLabel, HTML errorLabel) {
        button.setEnabled(true);
        statusLabel.setText(constants.statusNormal());
        resetStatusStyles(statusLabel);
        statusLabel.addStyleName("text-success"); //$NON-NLS-1$
        errorLabel.setHTML(""); //$NON-NLS-1$
        errorLabel.setVisible(false);
    }

    private void setFailedState(Button button, Label statusLabel, HTML errorLabel, FrontendActionAsyncResult result) {
        button.setEnabled(true);
        statusLabel.setText(constants.statusFailed());
        resetStatusStyles(statusLabel);
        statusLabel.addStyleName("text-danger"); //$NON-NLS-1$
        showErrorDetails(result, errorLabel);
    }

    private void resetStatusStyles(Label statusLabel) {
        statusLabel.removeStyleName("text-success"); //$NON-NLS-1$
        statusLabel.removeStyleName("text-danger"); //$NON-NLS-1$
        statusLabel.removeStyleName("text-warning"); //$NON-NLS-1$
    }

    private void executeSecurityAudit() {
        Frontend.getInstance().runAction(
            ActionType.SecurityAudit,
            new ActionParametersBase(),
            result -> {
                if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                    setNormalState(
                            securityAuditButton,
                            securityAuditStatusLabel,
                            securityAuditErrorLabel
                    );
                } else {
                    setFailedState(
                            securityAuditButton,
                            securityAuditStatusLabel,
                            securityAuditErrorLabel,
                            result
                    );
                }
                refreshVerificationHistoryAfterExecution();
            }
        );
    }

    private void executeIntegrityVerification() {
        Frontend.getInstance().runAction(
            ActionType.IntegrityVerification,
            new ActionParametersBase(),
            result -> {
                if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                    setNormalState(
                            integrityVerificationButton,
                            integrityVerificationStatusLabel,
                            integrityVerificationErrorLabel
                    );
                } else {
                    setFailedState(
                            integrityVerificationButton,
                            integrityVerificationStatusLabel,
                            integrityVerificationErrorLabel,
                            result
                    );
                }
                refreshVerificationHistoryAfterExecution();
            }
        );
    }

    private void loadVerificationHistory() {
        Frontend.getInstance().runQuery(
                QueryType.GetAllEventMessages,
                new QueryParametersBase(),
                new AsyncQuery<QueryReturnValue>(returnValue -> {
                    if (returnValue == null || !(returnValue.getReturnValue() instanceof List)) {
                        return;
                    }

                    List<AuditLog> securityAuditHistory = new ArrayList<>();
                    List<AuditLog> integrityVerificationHistory = new ArrayList<>();
                    for (Object entry : (List<?>) returnValue.getReturnValue()) {
                        if (!(entry instanceof AuditLog)) {
                            continue;
                        }

                        AuditLog auditLog = (AuditLog) entry;
                        if (isSecurityAuditResult(auditLog.getLogType())) {
                            securityAuditHistory.add(auditLog);
                        } else if (isIntegrityVerificationResult(auditLog.getLogType())) {
                            integrityVerificationHistory.add(auditLog);
                        }
                    }

                    securityAuditHistoryLabel.setHTML(formatHistory(securityAuditHistory));
                    integrityVerificationHistoryLabel.setHTML(formatHistory(integrityVerificationHistory));
                }));
    }

    private void refreshVerificationHistoryAfterExecution() {
        new Timer() {
            private int attempts;

            @Override
            public void run() {
                loadVerificationHistory();
                attempts++;
                if (attempts < HISTORY_REFRESH_ATTEMPTS) {
                    schedule(HISTORY_REFRESH_DELAY_MILLIS);
                }
            }
        }.schedule(HISTORY_REFRESH_DELAY_MILLIS);
    }

    private boolean isSecurityAuditResult(AuditLogType logType) {
        return logType == AuditLogType.SECURITY_AUDIT_STARTED ||
                logType == AuditLogType.SECURITY_AUDIT_COMPLETED ||
                logType == AuditLogType.SECURITY_AUDIT_FAILED ||
                logType == AuditLogType.SECURITY_AUDIT_WARNING;
    }

    private boolean isIntegrityVerificationResult(AuditLogType logType) {
        return logType == AuditLogType.INTEGRITY_VERIFICATION_STARTED ||
                logType == AuditLogType.INTEGRITY_VERIFICATION_COMPLETED ||
                logType == AuditLogType.INTEGRITY_VERIFICATION_FAILED ||
                logType == AuditLogType.INTEGRITY_VERIFICATION_WARNING;
    }

    private String formatHistory(List<AuditLog> history) {
        Collections.sort(history, new Comparator<AuditLog>() {
            @Override
            public int compare(AuditLog first, AuditLog second) {
                Date firstTime = first.getLogTime();
                Date secondTime = second.getLogTime();
                return secondTime.compareTo(firstTime);
            }
        });

        if (history.isEmpty()) {
            return SafeHtmlUtils.fromString("실행 이력이 없습니다.").asString(); //$NON-NLS-1$
        }

        StringBuilder result = new StringBuilder();
        int count = Math.min(HISTORY_LIMIT, history.size());
        for (int index = 0; index < count; index++) {
            AuditLog auditLog = history.get(index);
            if (index > 0) {
                result.append("<br/>"); //$NON-NLS-1$
            }
            String entry = HISTORY_TIME_FORMAT.format(auditLog.getLogTime())
                    + " | " //$NON-NLS-1$
                    + getHistoryStatus(auditLog.getLogType())
                    + " | " //$NON-NLS-1$
                    + auditLog.getUserName();
            result.append(SafeHtmlUtils.fromString(entry).asString());
        }
        return result.toString();
    }

    private String getHistoryStatus(AuditLogType logType) {
        if (logType == AuditLogType.SECURITY_AUDIT_STARTED ||
                logType == AuditLogType.INTEGRITY_VERIFICATION_STARTED) {
            return "실행 중"; //$NON-NLS-1$
        }
        if (logType == AuditLogType.SECURITY_AUDIT_COMPLETED ||
                logType == AuditLogType.INTEGRITY_VERIFICATION_COMPLETED) {
            return "성공"; //$NON-NLS-1$
        }
        if (logType == AuditLogType.SECURITY_AUDIT_WARNING ||
                logType == AuditLogType.INTEGRITY_VERIFICATION_WARNING) {
            return "경고"; //$NON-NLS-1$
        }
        return "실패"; //$NON-NLS-1$
    }

    private void showErrorDetails(FrontendActionAsyncResult result, HTML errorLabel) {
        StringBuilder errorMsg = new StringBuilder();

        if (result != null && result.getReturnValue() != null) {
            if (result.getReturnValue().getExecuteFailedMessages() != null
                    && !result.getReturnValue().getExecuteFailedMessages().isEmpty()) {
                for (String msg : result.getReturnValue().getExecuteFailedMessages()) {
                    if (msg != null && !msg.trim().isEmpty()) {
                        errorMsg.append(msg).append("\n"); //$NON-NLS-1$
                    }
                }
            }

            Object actionReturnValue = result.getReturnValue().getActionReturnValue();
            if (actionReturnValue instanceof String) {
                String output = ((String) actionReturnValue).trim();
                if (!output.isEmpty()) {
                    if (errorMsg.length() > 0) {
                        errorMsg.append("\n"); //$NON-NLS-1$
                    }
                    errorMsg.append(output);
                }
            }
        }

        if (errorMsg.length() == 0) {
            errorMsg.append("오류가 발생했습니다. 다시 실행해 주세요."); //$NON-NLS-1$
        }

        String htmlContent = SafeHtmlUtils.fromString(errorMsg.toString().trim())
                .asString()
                .replace("\n", "<br/>"); //$NON-NLS-1$ //$NON-NLS-2$
        errorLabel.setHTML(htmlContent);
        errorLabel.setVisible(true);
    }
}
