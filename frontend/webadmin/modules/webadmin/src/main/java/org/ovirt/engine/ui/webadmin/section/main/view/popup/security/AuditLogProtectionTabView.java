package org.ovirt.engine.ui.webadmin.section.main.view.popup.security;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

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
import com.google.gwt.user.client.ui.ListBox;
import com.google.gwt.user.client.ui.TextBox;
import com.google.gwt.user.client.ui.Widget;

public class AuditLogProtectionTabView extends Composite {

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

    public AuditLogProtectionTabView() {
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        initializeHandlers();
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
            fullLogBackupResultLabel.setText("처리 중..."); //$NON-NLS-1$
            Frontend.getInstance().runAction(ActionType.FullLogBackup, parameters, result -> {
                handleResult(result, buildSuccessMessage(backupPath), fullLogBackupResultLabel);
            });
        });

        refreshBackupListButton.addClickHandler((ClickHandler) event -> refreshBackupList());

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
