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
import com.google.gwt.user.client.Window;
import com.google.gwt.user.client.ui.Composite;
import com.google.gwt.user.client.ui.HTML;
import com.google.gwt.user.client.ui.Label;
import com.google.gwt.user.client.ui.Widget;

public class IntegrityCheckView extends Composite {
    private static final int HISTORY_LIMIT = 10;
    private static final int HISTORY_REFRESH_ATTEMPTS = 5;
    private static final int HISTORY_REFRESH_DELAY_MILLIS = 1000;
    private static final DateTimeFormat HISTORY_TIME_FORMAT = DateTimeFormat.getFormat("yyyy-MM-dd HH:mm:ss"); //$NON-NLS-1$
    private static final String SECURITY_AUDIT_NAME = "자체 보안 검증"; //$NON-NLS-1$
    private static final String INTEGRITY_VERIFICATION_NAME = "무결성 검사"; //$NON-NLS-1$
    private static final String NO_HALT_HISTORY = "서비스 중단 이력이 없습니다."; //$NON-NLS-1$

    /**
     * The reason codes the start gate writes, as SecurityAuditRunner.BlockedStart spells them.
     *
     * <p>Named here rather than read out of the record's message: the code is what the engine puts
     * in the record's custom data for this screen to read, and the message is prose.</p>
     */
    private static final String HALT_REASON_CHECKS_FAILED = "SECURITY_CHECKS_FAILED"; //$NON-NLS-1$
    private static final String HALT_REASON_BUSY = "VERIFICATION_BUSY"; //$NON-NLS-1$
    private static final String HALT_REASON_RUNNER_MISSING = "RUNNER_MISSING"; //$NON-NLS-1$
    private static final String HALT_REASON_ERROR = "VERIFICATION_ERROR"; //$NON-NLS-1$
    /** Written by ScheduledVerificationFailureResponse when a scheduled run stops a running engine. */
    private static final String HALT_REASON_SCHEDULED = "SCHEDULED_VERIFICATION_FAILED"; //$NON-NLS-1$
    /** The same, when the run was started from this screen. */
    private static final String HALT_REASON_MANUAL = "MANUAL_VERIFICATION_FAILED"; //$NON-NLS-1$
    /** The same, when the integrity verification run at engine start failed. */
    private static final String HALT_REASON_START = "START_VERIFICATION_FAILED"; //$NON-NLS-1$
    private static final String HALT_REASON_POST_START = "POST_START_VERIFICATION_FAILED"; //$NON-NLS-1$

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
    HTML securityAuditResultTable;

    @UiField
    HTML integrityVerificationResultTable;

    @UiField
    HTML integrityVerificationHistoryLabel;

    @UiField
    HTML serviceHaltAlertLabel;

    @UiField
    HTML serviceHaltClearLabel;

    @UiField
    HTML serviceHaltHistoryLabel;

    private boolean securityAuditRunning;
    private boolean integrityVerificationRunning;

    public IntegrityCheckView() {
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        securityAuditHistoryLabel.setHTML(SafeHtmlUtils.fromString("실행 이력이 없습니다.").asString()); //$NON-NLS-1$
        securityAuditResultTable.setHTML(formatResults(new ArrayList<VerificationResults.Row>(), "항목", //$NON-NLS-1$
                "자체시험 결과가 없습니다.")); //$NON-NLS-1$
        integrityVerificationResultTable.setHTML(formatResults(new ArrayList<VerificationResults.Row>(), "구분", //$NON-NLS-1$
                "무결성 검사 결과가 없습니다.")); //$NON-NLS-1$
        integrityVerificationHistoryLabel.setHTML(SafeHtmlUtils.fromString("실행 이력이 없습니다.").asString()); //$NON-NLS-1$
        serviceHaltHistoryLabel.setHTML(SafeHtmlUtils.fromString(NO_HALT_HISTORY).asString());
        initializeHandlers();
    }

    @Override
    protected void onLoad() {
        super.onLoad();
        loadVerificationHistory(true);
    }

    private void initializeHandlers() {
        securityAuditButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                securityAuditRunning = true;
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
                integrityVerificationRunning = true;
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

    private void setFailedState(String checkName, Button button, Label statusLabel, HTML errorLabel,
            FrontendActionAsyncResult result) {
        button.setEnabled(true);
        statusLabel.setText(constants.statusFailed());
        resetStatusStyles(statusLabel);
        statusLabel.addStyleName("text-danger"); //$NON-NLS-1$
        String details = collectErrorDetails(result);
        showErrorDetails(details, errorLabel);
        alertFailure(checkName, details);
    }

    /**
     * Puts a failed verification in front of the administrator and waits to be acknowledged.
     *
     * <p>The status beside the button turns red and the reason appears underneath it, but a screen
     * that has been left open shows both to nobody. A verification that failed is the one result
     * on this screen that must not be able to go unread, so it is said in a window that has to be
     * dismissed before anything else can be done.</p>
     */
    private void alertFailure(String checkName, String details) {
        Window.alert(SecurityVerificationFailureAlert.message(checkName, details));
    }

    /**
     * A run whose items all passed but for some warnings reads "경고 (n건)" rather than "정상", so
     * that what the engine start only warned about - a process not yet running - is seen.
     */
    private void markWarnings(Label statusLabel, int warnings) {
        if (warnings <= 0 || !constants.statusNormal().equals(statusLabel.getText())) {
            return;
        }
        statusLabel.setText("경고 (" + warnings + "건)"); //$NON-NLS-1$ //$NON-NLS-2$
        resetStatusStyles(statusLabel);
        statusLabel.addStyleName("text-warning"); //$NON-NLS-1$
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
                securityAuditRunning = false;
                if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                    setNormalState(
                            securityAuditButton,
                            securityAuditStatusLabel,
                            securityAuditErrorLabel
                    );
                } else {
                    setFailedState(
                            SECURITY_AUDIT_NAME,
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
                integrityVerificationRunning = false;
                if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                    setNormalState(
                            integrityVerificationButton,
                            integrityVerificationStatusLabel,
                            integrityVerificationErrorLabel
                    );
                } else {
                    setFailedState(
                            INTEGRITY_VERIFICATION_NAME,
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

    private void loadVerificationHistory(boolean restoreStatuses) {
        Frontend.getInstance().runQuery(
                QueryType.GetAllEventMessages,
                new QueryParametersBase(),
                new AsyncQuery<QueryReturnValue>(returnValue -> {
                    if (returnValue == null || !(returnValue.getReturnValue() instanceof List)) {
                        return;
                    }

                    List<AuditLog> securityAuditHistory = new ArrayList<>();
                    List<AuditLog> integrityVerificationHistory = new ArrayList<>();
                    List<AuditLog> serviceHaltHistory = new ArrayList<>();
                    List<AuditLog> allEvents = new ArrayList<>();
                    for (Object entry : (List<?>) returnValue.getReturnValue()) {
                        if (!(entry instanceof AuditLog)) {
                            continue;
                        }

                        AuditLog auditLog = (AuditLog) entry;
                        allEvents.add(auditLog);
                        if (isSecurityAuditResult(auditLog.getLogType())) {
                            securityAuditHistory.add(auditLog);
                        } else if (isIntegrityVerificationResult(auditLog.getLogType())) {
                            integrityVerificationHistory.add(auditLog);
                        } else if (auditLog.getLogType() == AuditLogType.SECURITY_VERIFICATION_SERVICE_HALTED) {
                            serviceHaltHistory.add(auditLog);
                        }
                    }

                    List<VerificationResults.Row> selfTest = VerificationResults.latestSelfTest(allEvents);
                    securityAuditResultTable.setHTML(formatResults(selfTest,
                            "항목", "자체시험 결과가 없습니다.")); //$NON-NLS-1$ //$NON-NLS-2$
                    integrityVerificationResultTable.setHTML(formatResults(
                            VerificationResults.latestIntegrity(allEvents),
                            "구분", "무결성 검사 결과가 없습니다.")); //$NON-NLS-1$ //$NON-NLS-2$
                    securityAuditHistoryLabel.setHTML(formatHistory(securityAuditHistory));
                    integrityVerificationHistoryLabel.setHTML(formatHistory(integrityVerificationHistory));
                    showServiceHalts(serviceHaltHistory);
                    if (restoreStatuses) {
                        if (!securityAuditRunning) {
                            restoreLastExecutionState(
                                    securityAuditHistory,
                                    securityAuditButton,
                                    securityAuditStatusLabel,
                                    securityAuditErrorLabel);
                        }
                        if (!integrityVerificationRunning) {
                            restoreLastExecutionState(
                                    integrityVerificationHistory,
                                    integrityVerificationButton,
                                    integrityVerificationStatusLabel,
                                    integrityVerificationErrorLabel);
                        }
                    }
                    if (!securityAuditRunning) {
                        markWarnings(securityAuditStatusLabel,
                                VerificationResults.count(selfTest, "경고")); //$NON-NLS-1$
                    }
                }));
    }

    private void restoreLastExecutionState(List<AuditLog> history, Button button, Label statusLabel, HTML errorLabel) {
        AuditLog latestResult = getLatestResult(history);
        if (latestResult == null) {
            return;
        }

        AuditLogType logType = latestResult.getLogType();
        if (logType == AuditLogType.SECURITY_AUDIT_COMPLETED ||
                logType == AuditLogType.INTEGRITY_VERIFICATION_COMPLETED) {
            setNormalState(button, statusLabel, errorLabel);
        } else {
            setFailedState(button, statusLabel, errorLabel);
        }
    }

    private AuditLog getLatestResult(List<AuditLog> history) {
        AuditLog latestResult = null;
        for (AuditLog auditLog : history) {
            if (auditLog.getLogType() == AuditLogType.SECURITY_AUDIT_STARTED ||
                    auditLog.getLogType() == AuditLogType.INTEGRITY_VERIFICATION_STARTED) {
                continue;
            }
            if (latestResult == null || auditLog.getLogTime().after(latestResult.getLogTime())) {
                latestResult = auditLog;
            }
        }
        return latestResult;
    }

    private void setFailedState(Button button, Label statusLabel, HTML errorLabel) {
        button.setEnabled(true);
        statusLabel.setText(constants.statusFailed());
        resetStatusStyles(statusLabel);
        statusLabel.addStyleName("text-danger"); //$NON-NLS-1$
        errorLabel.setHTML(""); //$NON-NLS-1$
        errorLabel.setVisible(false);
    }

    private void refreshVerificationHistoryAfterExecution() {
        new Timer() {
            private int attempts;

            @Override
            public void run() {
                loadVerificationHistory(false);
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

    /**
     * The latest run, item by item: process, item, result, what was found and when.
     *
     * <p>Every item of every process, the ones that passed as well, so that this screen shows the
     * run itself and not only whether it passed.</p>
     */
    private String formatResults(List<VerificationResults.Row> rows, String itemHeading, String empty) {
        if (rows.isEmpty()) {
            return SafeHtmlUtils.fromString(empty).asString();
        }
        StringBuilder html = new StringBuilder(
                "<table class=\"table table-condensed table-bordered\" style=\"margin:0\">" //$NON-NLS-1$
                        + "<thead><tr><th>프로세스</th><th>" + SafeHtmlUtils.htmlEscape(itemHeading) //$NON-NLS-1$
                        + "</th><th>결과</th><th>내용</th><th>시각</th></tr></thead>" //$NON-NLS-1$
                        + "<tbody>"); //$NON-NLS-1$
        for (VerificationResults.Row row : rows) {
            html.append("<tr><td>").append(SafeHtmlUtils.htmlEscape(row.getProcess())) //$NON-NLS-1$
                    .append("</td><td>").append(SafeHtmlUtils.htmlEscape(row.getItem())) //$NON-NLS-1$
                    .append("</td><td class=\"").append(resultStyle(row.getResult())).append("\"><b>") //$NON-NLS-1$ //$NON-NLS-2$
                    .append(SafeHtmlUtils.htmlEscape(row.getResult()))
                    .append("</b></td><td>").append(SafeHtmlUtils.htmlEscape(row.getText())) //$NON-NLS-1$
                    .append("</td><td>") //$NON-NLS-1$
                    .append(row.getTime() == null ? "" : HISTORY_TIME_FORMAT.format(row.getTime())) //$NON-NLS-1$
                    .append("</td></tr>"); //$NON-NLS-1$
        }
        return html.append("</tbody></table>").toString(); //$NON-NLS-1$
    }

    private static String resultStyle(String result) {
        if ("성공".equals(result)) { //$NON-NLS-1$
            return "text-success"; //$NON-NLS-1$
        }
        if ("실패".equals(result)) { //$NON-NLS-1$
            return "text-danger"; //$NON-NLS-1$
        }
        if ("경고".equals(result)) { //$NON-NLS-1$
            return "text-warning"; //$NON-NLS-1$
        }
        return "text-muted"; //$NON-NLS-1$
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

    /**
     * Shows what was done about a verification that did not pass: the service was not started.
     *
     * <p>The response cannot report itself while it is in effect - a refused start produces no
     * engine, so nothing writes to the event list and nothing serves this screen. The start gate
     * records each refusal instead, and this is where the record is read back: how many there
     * have been, when, and why, so that an administrator who has just recovered the service can
     * see on a screen that it was stopped rather than having to be told.</p>
     */
    private void showServiceHalts(List<AuditLog> halts) {
        boolean halted = !halts.isEmpty();
        serviceHaltAlertLabel.setVisible(halted);
        serviceHaltClearLabel.setVisible(!halted);
        if (halted) {
            AuditLog latest = getLatestHalt(halts);
            serviceHaltAlertLabel.setHTML(SafeHtmlUtils.fromString(
                    "보안 검증 실패로 엔진 서비스가 중단된 이력이 " + halts.size() + "건 있습니다." //$NON-NLS-1$ //$NON-NLS-2$
                            + " 최근 중단: " + HISTORY_TIME_FORMAT.format(latest.getLogTime()) //$NON-NLS-1$
                            + " (" + haltReason(latest) + ")").asString()); //$NON-NLS-1$ //$NON-NLS-2$
        } else {
            serviceHaltClearLabel.setHTML(SafeHtmlUtils.fromString(
                    "보안 검증 실패로 서비스가 중단된 이력이 없습니다.").asString()); //$NON-NLS-1$
        }
        serviceHaltHistoryLabel.setHTML(formatHaltHistory(halts));
    }

    private AuditLog getLatestHalt(List<AuditLog> halts) {
        AuditLog latest = halts.get(0);
        for (AuditLog halt : halts) {
            if (halt.getLogTime().after(latest.getLogTime())) {
                latest = halt;
            }
        }
        return latest;
    }

    private String formatHaltHistory(List<AuditLog> halts) {
        if (halts.isEmpty()) {
            return SafeHtmlUtils.fromString(NO_HALT_HISTORY).asString();
        }

        List<AuditLog> sorted = new ArrayList<>(halts);
        Collections.sort(sorted, new Comparator<AuditLog>() {
            @Override
            public int compare(AuditLog first, AuditLog second) {
                return second.getLogTime().compareTo(first.getLogTime());
            }
        });

        StringBuilder result = new StringBuilder();
        int count = Math.min(HISTORY_LIMIT, sorted.size());
        for (int index = 0; index < count; index++) {
            AuditLog halt = sorted.get(index);
            if (index > 0) {
                result.append("<br/>"); //$NON-NLS-1$
            }
            String entry = HISTORY_TIME_FORMAT.format(halt.getLogTime())
                    + " | 서비스 중단 | " //$NON-NLS-1$
                    + haltReason(halt)
                    + " | " //$NON-NLS-1$
                    + (halt.getMessage() == null ? "" : halt.getMessage()); //$NON-NLS-1$
            result.append(SafeHtmlUtils.fromString(entry).asString());
        }
        return result.toString();
    }

    /**
     * Names the reason in Korean, from the code the record carries rather than from its message.
     *
     * <p>The engine writes the reason code beside the message for this: reading the reason out of
     * English prose would break the moment that prose was reworded. A code this does not know is
     * shown as it stands, which is still an answer.</p>
     */
    private String haltReason(AuditLog halt) {
        String reason = halt.getCustomData() == null ? "" : halt.getCustomData().trim(); //$NON-NLS-1$
        if (HALT_REASON_CHECKS_FAILED.equals(reason)) {
            return "자체 보안 검증 항목 실패"; //$NON-NLS-1$
        }
        if (HALT_REASON_BUSY.equals(reason)) {
            return "다른 보안 검증 실행 중으로 검증 불가"; //$NON-NLS-1$
        }
        if (HALT_REASON_RUNNER_MISSING.equals(reason)) {
            return "보안 검증 실행기 없음"; //$NON-NLS-1$
        }
        if (HALT_REASON_ERROR.equals(reason)) {
            return "보안 검증 수행 오류"; //$NON-NLS-1$
        }
        if (HALT_REASON_SCHEDULED.equals(reason)) {
            return "정기 보안 검증(타이머) 실패"; //$NON-NLS-1$
        }
        if (HALT_REASON_MANUAL.equals(reason)) {
            return "수동 보안 검증(관리 화면 실행) 실패"; //$NON-NLS-1$
        }
        if (HALT_REASON_START.equals(reason)) {
            return "엔진 기동 시 무결성 검사 실패"; //$NON-NLS-1$
        }
        if (HALT_REASON_POST_START.equals(reason)) {
            return "엔진 기동 후 자체 보안 검증 실패"; //$NON-NLS-1$
        }
        return reason.isEmpty() ? "사유 미기록" : reason; //$NON-NLS-1$
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

    private void showErrorDetails(String details, HTML errorLabel) {
        String htmlContent = SafeHtmlUtils.fromString(details)
                .asString()
                .replace("\n", "<br/>"); //$NON-NLS-1$ //$NON-NLS-2$
        errorLabel.setHTML(htmlContent);
        errorLabel.setVisible(true);
    }

    /** Everything the action said about why it failed, as plain text. */
    private String collectErrorDetails(FrontendActionAsyncResult result) {
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

        return errorMsg.toString().trim();
    }
}
