package org.ovirt.engine.ui.webadmin.section.main.view.popup.configure;

import org.gwtbootstrap3.client.ui.Button;
import org.ovirt.engine.core.common.action.ActionParametersBase;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.EngineConfigValueParameters;
import org.ovirt.engine.ui.frontend.Frontend;
import org.ovirt.engine.ui.uicompat.FrontendActionAsyncResult;

import com.google.gwt.core.client.GWT;
import com.google.gwt.safehtml.shared.SafeHtmlUtils;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.user.client.ui.Composite;
import com.google.gwt.user.client.ui.HTML;
import com.google.gwt.user.client.ui.IntegerBox;
import com.google.gwt.user.client.ui.Widget;

public class UserEnvironmentVariablesView extends Composite {

    private static final String MAX_LOGIN_MINUTES = "MAX_LOGIN_MINUTES"; //$NON-NLS-1$
    private static final String MAX_FAILURES_SINCE_SUCCESS = "MAX_FAILURES_SINCE_SUCCESS"; //$NON-NLS-1$

    interface ViewUiBinder extends UiBinder<Widget, UserEnvironmentVariablesView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    @UiField
    Button refreshButton;

    @UiField
    Button updateLoginMinutesButton;

    @UiField
    Button updateMaxFailuresButton;

    @UiField
    IntegerBox loginMinutesBox;

    @UiField
    IntegerBox maxFailuresBox;

    @UiField
    HTML settingsOutput;

    @UiField
    HTML resultLabel;

    public UserEnvironmentVariablesView() {
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        loginMinutesBox.setValue(60);
        maxFailuresBox.setValue(3);
        refreshButton.addClickHandler(event -> loadSettings());
        updateLoginMinutesButton.addClickHandler(event -> updateSetting(MAX_LOGIN_MINUTES, loginMinutesBox));
        updateMaxFailuresButton.addClickHandler(event -> updateSetting(MAX_FAILURES_SINCE_SUCCESS, maxFailuresBox));
        loadSettings();
    }

    private void loadSettings() {
        resultLabel.setText("사용자 전체 설정 값을 조회 중입니다..."); //$NON-NLS-1$
        Frontend.getInstance().runAction(ActionType.GetAaaJdbcSettings, new ActionParametersBase(), result -> {
            if (!isSuccessful(result)) {
                showFailure(result, "사용자 설정 조회에 실패했습니다."); //$NON-NLS-1$
                return;
            }
            String output = String.valueOf(result.getReturnValue().getActionReturnValue());
            settingsOutput.setHTML(asMultilineHtml(output));
            setParsedValue(output, MAX_LOGIN_MINUTES, loginMinutesBox);
            setParsedValue(output, MAX_FAILURES_SINCE_SUCCESS, maxFailuresBox);
            resultLabel.setText("조회 완료"); //$NON-NLS-1$
        });
    }

    private void updateSetting(String name, IntegerBox valueBox) {
        Integer value = valueBox.getValue();
        if (value == null || value <= 0) {
            resultLabel.setText("1 이상의 숫자를 입력해 주세요."); //$NON-NLS-1$
            return;
        }
        resultLabel.setText(name + " 수정 중..."); //$NON-NLS-1$
        Frontend.getInstance().runAction(ActionType.SetAaaJdbcSetting,
                new EngineConfigValueParameters(name, String.valueOf(value)), result -> {
                    if (isSuccessful(result)) {
                        resultLabel.setText("수정 완료"); //$NON-NLS-1$
                        loadSettings();
                    } else {
                        showFailure(result, "사용자 설정 수정에 실패했습니다."); //$NON-NLS-1$
                    }
                });
    }

    private boolean isSuccessful(FrontendActionAsyncResult result) {
        return result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded();
    }

    private void showFailure(FrontendActionAsyncResult result, String defaultMessage) {
        if (result != null && result.getReturnValue() != null
                && result.getReturnValue().getExecuteFailedMessages() != null
                && !result.getReturnValue().getExecuteFailedMessages().isEmpty()) {
            resultLabel.setHTML(asMultilineHtml(
                    String.join("\n", result.getReturnValue().getExecuteFailedMessages()))); //$NON-NLS-1$
        } else {
            resultLabel.setText(defaultMessage);
        }
    }

    private void setParsedValue(String output, String name, IntegerBox valueBox) {
        for (String line : output.split("\\r?\\n")) { //$NON-NLS-1$
            if (!line.contains(name)) {
                continue;
            }
            String suffix = line.substring(line.indexOf(name) + name.length()).trim();
            String[] tokens = suffix.split("[^0-9]+"); //$NON-NLS-1$
            for (String token : tokens) {
                if (!token.isEmpty()) {
                    valueBox.setValue(Integer.parseInt(token));
                    return;
                }
            }
        }
    }

    private String asMultilineHtml(String text) {
        return SafeHtmlUtils.fromString(text == null ? "" : text).asString() //$NON-NLS-1$
                .replace("\n", "<br/>"); //$NON-NLS-1$ //$NON-NLS-2$
    }
}
