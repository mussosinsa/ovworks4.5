package org.ovirt.engine.ui.webadmin.section.main.view.popup.configure;

import org.gwtbootstrap3.client.ui.Button;
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
import com.google.gwt.user.client.ui.TextBox;
import com.google.gwt.user.client.ui.Widget;

public class UserEnvironmentVariablesView extends Composite {

    private static final String MAX_LOGIN_MINUTES = "MAX_LOGIN_MINUTES"; //$NON-NLS-1$
    private static final String MAX_FAILURES_SINCE_SUCCESS = "MAX_FAILURES_SINCE_SUCCESS"; //$NON-NLS-1$
    private static final String MINIMUM_RESPONSE_SECONDS = "MINIMUM_RESPONSE_SECONDS"; //$NON-NLS-1$
    private static final int DEFAULT_MAX_LOGIN_MINUTES = 60;
    private static final int DEFAULT_MAX_FAILURES_SINCE_SUCCESS = 3;
    private static final int DEFAULT_MINIMUM_RESPONSE_SECONDS = 1;

    interface ViewUiBinder extends UiBinder<Widget, UserEnvironmentVariablesView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    @UiField
    Button refreshButton;

    @UiField
    TextBox settingNameBox;

    @UiField
    Button updateLoginMinutesButton;

    @UiField
    Button updateMaxFailuresButton;

    @UiField
    Button updateMinimumResponseSecondsButton;

    @UiField
    IntegerBox loginMinutesBox;

    @UiField
    IntegerBox maxFailuresBox;

    @UiField
    IntegerBox minimumResponseSecondsBox;

    @UiField
    HTML settingsOutput;

    @UiField
    HTML resultLabel;

    public UserEnvironmentVariablesView() {
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        loginMinutesBox.setValue(DEFAULT_MAX_LOGIN_MINUTES);
        maxFailuresBox.setValue(DEFAULT_MAX_FAILURES_SINCE_SUCCESS);
        minimumResponseSecondsBox.setValue(DEFAULT_MINIMUM_RESPONSE_SECONDS);
        refreshButton.addClickHandler(event -> querySetting());
        updateLoginMinutesButton.addClickHandler(event -> updateSetting(MAX_LOGIN_MINUTES, loginMinutesBox));
        updateMaxFailuresButton.addClickHandler(event -> updateSetting(MAX_FAILURES_SINCE_SUCCESS, maxFailuresBox));
        updateMinimumResponseSecondsButton.addClickHandler(
                event -> updateSetting(MINIMUM_RESPONSE_SECONDS, minimumResponseSecondsBox));
        resultLabel.setText("조회할 사용자 환경 변수 이름을 입력해 주세요."); //$NON-NLS-1$
    }

    private void querySetting() {
        String name = settingNameBox.getText() == null ? "" : settingNameBox.getText().trim(); //$NON-NLS-1$
        if (name.isEmpty()) {
            resultLabel.setText("조회할 사용자 환경 변수 이름을 입력해 주세요."); //$NON-NLS-1$
            return;
        }
        querySetting(name);
    }

    private void querySetting(String name) {
        resultLabel.setText(name + " 조회 중입니다..."); //$NON-NLS-1$
        Frontend.getInstance().runAction(ActionType.GetAaaJdbcSettings,
                new EngineConfigValueParameters(name), result -> {
            if (!isSuccessful(result)) {
                showFailure(result, "사용자 설정 조회에 실패했습니다."); //$NON-NLS-1$
                return;
            }
            Object payload = result.getReturnValue().getActionReturnValue();
            if (!(payload instanceof String)) {
                resultLabel.setText("사용자 설정 조회 결과 형식이 올바르지 않습니다."); //$NON-NLS-1$
                return;
            }
            String output = (String) payload;
            settingsOutput.setHTML(asMultilineHtml(output));
            if (MAX_LOGIN_MINUTES.equals(name)) {
                setParsedValue(output, name, loginMinutesBox);
            } else if (MAX_FAILURES_SINCE_SUCCESS.equals(name)) {
                setParsedValue(output, name, maxFailuresBox);
            } else if (MINIMUM_RESPONSE_SECONDS.equals(name)) {
                setParsedValue(output, name, minimumResponseSecondsBox);
            }
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
                        settingNameBox.setText(name);
                        querySetting(name);
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
