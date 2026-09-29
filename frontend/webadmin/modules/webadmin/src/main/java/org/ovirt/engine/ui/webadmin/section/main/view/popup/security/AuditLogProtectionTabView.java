package org.ovirt.engine.ui.webadmin.section.main.view.popup.security;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.gwtbootstrap3.client.ui.Button;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.AuditLogBackupParameters;
import org.ovirt.engine.core.common.businessentities.AuditLogCapacityStatus;
import org.ovirt.engine.core.common.queries.QueryParametersBase;
import org.ovirt.engine.core.common.queries.QueryReturnValue;
import org.ovirt.engine.core.common.queries.QueryType;
import org.ovirt.engine.ui.frontend.AsyncQuery;
import org.ovirt.engine.ui.frontend.Frontend;
import org.ovirt.engine.ui.uicompat.FrontendActionAsyncResult;

import com.google.gwt.core.client.GWT;
import com.google.gwt.event.dom.client.ClickHandler;
import com.google.gwt.i18n.client.DateTimeFormat;
import com.google.gwt.i18n.client.NumberFormat;
import com.google.gwt.safehtml.shared.SafeHtmlUtils;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.user.client.Timer;
import com.google.gwt.user.client.ui.Composite;
import com.google.gwt.user.client.ui.HTML;
import com.google.gwt.user.client.ui.Label;
import com.google.gwt.user.client.ui.ListBox;
import com.google.gwt.user.client.ui.TextBox;
import com.google.gwt.user.client.ui.Widget;

public class AuditLogProtectionTabView extends Composite {

    /**
     * How often the capacity reading is refreshed while the tab is open.
     *
     * <p>Long on purpose. The engine measures on its own schedule and this only reads what it
     * measured, so asking more often than it measures returns the same figure; a minute keeps the
     * screen current without a request per second on a tab that is often left open.</p>
     */
    private static final int CAPACITY_REFRESH_MILLIS = 60000;

    private static final DateTimeFormat CAPACITY_TIME_FORMAT =
            DateTimeFormat.getFormat("yyyy-MM-dd HH:mm:ss"); //$NON-NLS-1$

    private static final long BYTES_PER_MIB = 1024L * 1024L;

    interface ViewUiBinder extends UiBinder<Widget, AuditLogProtectionTabView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    @UiField
    Button fullLogBackupButton;

    @UiField
    Button refreshBackupListButton;

    @UiField
    Button restoreSelectedBackupButton;

    @UiField
    HTML fullLogBackupResultLabel;

    @UiField
    TextBox fullLogBackupPathInput;

    @UiField
    ListBox backupFileListBox;

    @UiField
    Label capacityStateLabel;

    @UiField
    Button refreshCapacityButton;

    @UiField
    HTML capacityGaugeLabel;

    @UiField
    HTML capacityDetailLabel;

    /** Runs while the tab is attached, so a tab left open does not keep asking after it is closed. */
    private Timer capacityRefreshTimer;

    public AuditLogProtectionTabView() {
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        initializeHandlers();
    }

    @Override
    protected void onLoad() {
        super.onLoad();
        loadCapacityStatus();
        if (capacityRefreshTimer == null) {
            capacityRefreshTimer = new Timer() {
                @Override
                public void run() {
                    loadCapacityStatus();
                }
            };
        }
        capacityRefreshTimer.scheduleRepeating(CAPACITY_REFRESH_MILLIS);
    }

    @Override
    protected void onUnload() {
        // A repeating timer outlives the screen that started it: left running, every tab the
        // administrator has ever opened would go on querying for as long as the browser is open.
        if (capacityRefreshTimer != null) {
            capacityRefreshTimer.cancel();
        }
        super.onUnload();
    }

    private void initializeHandlers() {
        fullLogBackupButton.addClickHandler((ClickHandler) event -> {
            String backupPath = fullLogBackupPathInput.getText().trim();
            if (backupPath.isEmpty()) {
                fullLogBackupResultLabel.setText("저장 위치를 입력해 주세요."); //$NON-NLS-1$
                return;
            }
            AuditLogBackupParameters parameters = new AuditLogBackupParameters();
            parameters.setBackupPath(backupPath);
            setBackupControlsEnabled(false);
            fullLogBackupResultLabel.setText("이벤트 DB 덤프 생성 중... 데이터 크기에 따라 시간이 걸릴 수 있습니다."); //$NON-NLS-1$
            Frontend.getInstance().runAction(ActionType.FullLogBackup, parameters, result -> {
                handleResult(result, buildSuccessMessage(backupPath), fullLogBackupResultLabel);
                setBackupControlsEnabled(true);
            });
        });

        refreshBackupListButton.addClickHandler((ClickHandler) event -> refreshBackupList());

        refreshCapacityButton.addClickHandler((ClickHandler) event -> loadCapacityStatus());

        restoreSelectedBackupButton.addClickHandler((ClickHandler) event -> {
            String backupPath = fullLogBackupPathInput.getText().trim();
            if (backupPath.isEmpty()) {
                fullLogBackupResultLabel.setText("저장 위치를 입력해 주세요."); //$NON-NLS-1$
                return;
            }
            if (backupFileListBox.getSelectedIndex() < 0) {
                fullLogBackupResultLabel.setText("복구할 감사기록 파일을 선택해 주세요."); //$NON-NLS-1$
                return;
            }

            String selectedFile = backupFileListBox.getSelectedValue();
            restoreSelectedBackupAfterLookup(backupPath, selectedFile);
        });
    }

    private void restoreSelectedBackupAfterLookup(String backupPath, String selectedFile) {
        AuditLogBackupParameters listParameters = new AuditLogBackupParameters();
        listParameters.setBackupPath(backupPath);
        fullLogBackupResultLabel.setText("복구 전 감사기록 목록 조회 중..."); //$NON-NLS-1$

        Frontend.getInstance().runAction(ActionType.ListAuditLogBackups, listParameters, listResult -> {
            List<String> files = getBackupFiles(listResult);
            if (files == null) {
                handleResult(listResult, "", fullLogBackupResultLabel); //$NON-NLS-1$
                return;
            }
            if (!files.contains(selectedFile)) {
                fullLogBackupResultLabel.setText("선택한 감사기록 백업 파일을 저장 위치에서 찾을 수 없습니다. 목록을 다시 조회해 주세요."); //$NON-NLS-1$
                return;
            }

            AuditLogBackupParameters restoreParameters = new AuditLogBackupParameters();
            restoreParameters.setBackupPath(backupPath);
            restoreParameters.setSelectedBackupFile(selectedFile);
            fullLogBackupResultLabel.setText("감사기록 목록 조회 완료. 복구 처리 중..."); //$NON-NLS-1$
            Frontend.getInstance().runAction(ActionType.RestoreAuditLogBackup, restoreParameters, restoreResult -> {
                handleResult(restoreResult,
                        "복구 완료\n현재 이벤트 데이터를 먼저 백업한 후 선택한 DB 덤프를 복구했습니다.", //$NON-NLS-1$
                        fullLogBackupResultLabel);
                refreshBackupList();
            });
        });
    }

    private void refreshBackupList() {
        String backupPath = fullLogBackupPathInput.getText().trim();
        if (backupPath.isEmpty()) {
            fullLogBackupResultLabel.setText("저장 위치를 입력해 주세요."); //$NON-NLS-1$
            return;
        }

        AuditLogBackupParameters parameters = new AuditLogBackupParameters();
        parameters.setBackupPath(backupPath);
        fullLogBackupResultLabel.setText("감사기록 목록 조회 중..."); //$NON-NLS-1$

        Frontend.getInstance().runAction(ActionType.ListAuditLogBackups, parameters, result -> {
            StringBuilder details = new StringBuilder();
            backupFileListBox.clear();

            if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                List<String> files = getBackupFiles(result);
                if (files.isEmpty()) {
                    details.append("조회된 감사기록 백업 파일이 없습니다."); //$NON-NLS-1$
                } else {
                    files.forEach(file -> backupFileListBox.addItem(file, file));
                    details.append("감사기록 백업 목록 조회 완료: ").append(files.size()).append("건"); //$NON-NLS-1$ //$NON-NLS-2$
                }
                fullLogBackupResultLabel.setHTML(formatHtml(details.toString()));
                return;
            }

            if (result != null && result.getReturnValue() != null
                    && result.getReturnValue().getExecuteFailedMessages() != null) {
                result.getReturnValue().getExecuteFailedMessages().forEach(msg -> {
                    details.append(msg).append("\n"); //$NON-NLS-1$
                });
            }
            if (details.length() == 0) {
                details.append("감사기록 목록 조회 중 오류가 발생했습니다."); //$NON-NLS-1$
            }
            fullLogBackupResultLabel.setHTML(formatHtml(details.toString().trim()));
        });
    }

    /**
     * Asks the engine how full the audit-record storage is, and shows the answer.
     *
     * <p>What fills up is a directory on the engine host, so the figure cannot come from a search:
     * it comes from the component that is already measuring it. A reading that cannot be taken is
     * shown as such rather than as zero, which would read as an empty storage.</p>
     */
    private void loadCapacityStatus() {
        Frontend.getInstance().runQuery(
                QueryType.GetAuditLogCapacityStatus,
                new QueryParametersBase(),
                new AsyncQuery<QueryReturnValue>(returnValue -> {
                    if (returnValue == null || returnValue.getReturnValue() == null
                            || !(returnValue.getReturnValue() instanceof AuditLogCapacityStatus)) {
                        showCapacityUnreadable();
                        return;
                    }
                    showCapacity((AuditLogCapacityStatus) returnValue.getReturnValue());
                }));
    }

    private void showCapacityUnreadable() {
        capacityStateLabel.setText("조회 실패"); //$NON-NLS-1$
        setCapacityStateColour("#a94442"); //$NON-NLS-1$
        capacityGaugeLabel.setHTML(gauge(0, "#dddddd")); //$NON-NLS-1$
        capacityDetailLabel.setHTML(formatHtml(
                "감사기록 저장소 용량을 조회할 수 없습니다. 엔진 서비스 상태를 확인해 주세요.")); //$NON-NLS-1$
    }

    private void showCapacity(AuditLogCapacityStatus status) {
        capacityStateLabel.setText(stateName(status));
        setCapacityStateColour(stateColour(status));
        capacityGaugeLabel.setHTML(status.isMeasured()
                ? gauge(status.getUsedPercent(), stateColour(status))
                : gauge(0, "#dddddd")); //$NON-NLS-1$
        capacityDetailLabel.setHTML(formatHtml(capacityDetail(status)));
    }

    private String capacityDetail(AuditLogCapacityStatus status) {
        StringBuilder detail = new StringBuilder();
        detail.append("저장 위치: ").append(status.getDirectory()); //$NON-NLS-1$
        switch (status.getState()) {
            case DISABLED:
                // Not a fault, and not something to be inferred from a blank panel: the limit or
                // the interval is set to zero, so nothing is being measured at all.
                detail.append("\n감시 상태: 사용량 감시가 설정으로 중지되어 있습니다.") //$NON-NLS-1$
                        .append("\n감시를 사용하려면 ENGINE_AUDIT_LOG_MAX_SIZE_MB 및 ") //$NON-NLS-1$
                        .append("ENGINE_AUDIT_LOG_CAPACITY_CHECK_INTERVAL_SECONDS 를 ") //$NON-NLS-1$
                        .append("1 이상으로 설정한 뒤 엔진을 재시작하십시오."); //$NON-NLS-1$
                return detail.toString();
            case UNAVAILABLE:
                detail.append("\n감시 상태: 사용량을 측정할 수 없습니다."); //$NON-NLS-1$
                if (!status.getUnavailableReason().isEmpty()) {
                    detail.append("\n사유: ").append(status.getUnavailableReason()); //$NON-NLS-1$
                }
                break;
            default:
                detail.append("\n사용량: ").append(mib(status.getUsedBytes())) //$NON-NLS-1$
                        .append(" MiB / 한도 ").append(mib(status.getMaxBytes())) //$NON-NLS-1$
                        .append(" MiB (").append(status.getUsedPercent()).append("% 사용, 잔여 ") //$NON-NLS-1$ //$NON-NLS-2$
                        .append(status.getRemainingPercent()).append("%)"); //$NON-NLS-1$
                detail.append("\n경고 임계값: 잔여 ").append(status.getWarningRemainingPercent()) //$NON-NLS-1$
                        .append("% 이하"); //$NON-NLS-1$
                break;
        }
        detail.append("\n측정 시각: ").append(status.getMeasuredAt() == null //$NON-NLS-1$
                ? "없음" //$NON-NLS-1$
                : CAPACITY_TIME_FORMAT.format(status.getMeasuredAt()));
        // Said because the two are not the same thing: a reading taken for this request is current
        // to the second, and the monitor's is as old as its interval.
        detail.append(status.isMeasuredOnDemand()
                ? " (이번 조회 시 측정)" //$NON-NLS-1$
                : " (감시 주기 " + status.getCheckIntervalSeconds() + "초)"); //$NON-NLS-1$ //$NON-NLS-2$
        return detail.toString();
    }

    private static String stateName(AuditLogCapacityStatus status) {
        switch (status.getState()) {
            case NORMAL:
                return "정상"; //$NON-NLS-1$
            case WARNING:
                return "경고 (잔여 용량 부족)"; //$NON-NLS-1$
            case EXCEEDED:
                return "초과 (한도 도달)"; //$NON-NLS-1$
            case DISABLED:
                return "감시 중지"; //$NON-NLS-1$
            default:
                return "측정 불가"; //$NON-NLS-1$
        }
    }

    private static String stateColour(AuditLogCapacityStatus status) {
        switch (status.getState()) {
            case NORMAL:
                return "#3c763d"; //$NON-NLS-1$
            case WARNING:
                return "#8a6d3b"; //$NON-NLS-1$
            case EXCEEDED:
                return "#a94442"; //$NON-NLS-1$
            default:
                return "#5b6773"; //$NON-NLS-1$
        }
    }

    private void setCapacityStateColour(String colour) {
        capacityStateLabel.getElement().getStyle().setProperty("color", colour); //$NON-NLS-1$
    }

    /**
     * The filled part of the bar.
     *
     * <p>Both values are produced here - a whole number between 0 and 100, and one of four colours
     * named above - so nothing a caller supplies reaches the markup.</p>
     */
    private static String gauge(long usedPercent, String colour) {
        long width = usedPercent < 0 ? 0 : (usedPercent > 100 ? 100 : usedPercent);
        return "<div style=\"width:" + width //$NON-NLS-1$
                + "%;height:100%;background-color:" + colour //$NON-NLS-1$
                + ";\"></div>"; //$NON-NLS-1$
    }

    /** Whole MiB, as the engine's own capacity events report it. */
    private static String mib(long bytes) {
        return NumberFormat.getDecimalFormat().format(bytes / BYTES_PER_MIB);
    }

    private List<String> getBackupFiles(FrontendActionAsyncResult result) {
        if (result == null || result.getReturnValue() == null || !result.getReturnValue().getSucceeded()) {
            return null;
        }

        Object value = result.getReturnValue().getActionReturnValue();
        List<String> files = new ArrayList<>();
        if (value instanceof List<?>) {
            for (Object item : (List<?>) value) {
                if (item != null) {
                    files.add(item.toString());
                }
            }
        }
        return files;
    }

    private String buildSuccessMessage(String backupPath) {
        return "처리날짜 : " + currentTimestamp() + " - 정상저장\n" //$NON-NLS-1$ //$NON-NLS-2$
                + "이벤트 테이블 압축 DB 덤프: " + backupPath; //$NON-NLS-1$
    }

    private void setBackupControlsEnabled(boolean enabled) {
        fullLogBackupButton.setEnabled(enabled);
        refreshBackupListButton.setEnabled(enabled);
        restoreSelectedBackupButton.setEnabled(enabled);
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
            details.append("백업 실행 중 오류가 발생했습니다."); //$NON-NLS-1$
        }
        target.setHTML(formatHtml(details.toString().trim()));
    }

    private String formatHtml(String message) {
        return SafeHtmlUtils.fromString(message).asString().replace("\n", "<br/>"); //$NON-NLS-1$ //$NON-NLS-2$
    }
}
