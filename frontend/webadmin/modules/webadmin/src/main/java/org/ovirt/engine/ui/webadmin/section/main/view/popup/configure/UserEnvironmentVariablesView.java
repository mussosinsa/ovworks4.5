package org.ovirt.engine.ui.webadmin.section.main.view.popup.configure;

import java.util.HashMap;
import java.util.Map;

import org.gwtbootstrap3.client.ui.Button;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.EngineConfigValueParameters;
import org.ovirt.engine.ui.frontend.Frontend;

import com.google.gwt.core.client.GWT;
import com.google.gwt.safehtml.shared.SafeHtmlUtils;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.user.client.ui.Composite;
import com.google.gwt.user.client.ui.HTML;
import com.google.gwt.user.client.ui.TextBox;
import com.google.gwt.user.client.ui.Widget;

public class UserEnvironmentVariablesView extends Composite {

    private static final String MAX_FAILURES_SINCE_SUCCESS = "MAX_FAILURES_SINCE_SUCCESS"; //$NON-NLS-1$

    interface ViewUiBinder extends UiBinder<Widget, UserEnvironmentVariablesView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    @UiField TextBox keyTextBox;
    @UiField TextBox maxFailuresTextBox;
    @UiField Button queryButton;
    @UiField Button updateMaxFailuresButton;
    @UiField HTML commandLabel;
    @UiField HTML outputLabel;
    @UiField HTML resultLabel;

    private final Map<String, TextBox> fieldsByKey = new HashMap<>();

    public UserEnvironmentVariablesView() {
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        fieldsByKey.put(MAX_FAILURES_SINCE_SUCCESS, maxFailuresTextBox);

        queryButton.addClickHandler(event -> querySelectedValue());
        updateMaxFailuresButton.addClickHandler(event -> updateValue(MAX_FAILURES_SINCE_SUCCESS));
        keyTextBox.setText(MAX_FAILURES_SINCE_SUCCESS);
        queryAllValues();
    }

    private void queryAllValues() {
        for (String key : fieldsByKey.keySet()) {
            queryValue(key, false);
        }
    }

    private void querySelectedValue() {
        String key = keyTextBox.getText() == null ? "" : keyTextBox.getText().trim(); //$NON-NLS-1$
        if (!fieldsByKey.containsKey(key)) {
            resultLabel.setText("지원하지 않는 사용자 환경 변수입니다."); //$NON-NLS-1$
            return;
        }
        queryValue(key, true);
    }

    private void queryValue(String key, boolean showOutput) {
        Frontend.getInstance().runAction(ActionType.GetUserEnvironmentVariable,
                new EngineConfigValueParameters(key), result -> {
                    if (result == null || result.getReturnValue() == null || !result.getReturnValue().getSucceeded()) {
                        resultLabel.setText("조회 실패: " + key); //$NON-NLS-1$
                        return;
                    }
                    Object value = result.getReturnValue().getActionReturnValue();
                    String output = value == null ? "" : value.toString(); //$NON-NLS-1$
                    fieldsByKey.get(key).setText(extractValue(output));
                    if (showOutput) {
                        commandLabel.setText("ovirt-aaa-jdbc-tool settings show --name=" + key); //$NON-NLS-1$
                        outputLabel.setHTML(toHtml(output));
                        resultLabel.setText("조회 완료"); //$NON-NLS-1$
                    }
                }, false);
    }

    private void updateValue(String key) {
        String value = fieldsByKey.get(key).getText().trim();
        if (!value.matches("[0-9]+")) { //$NON-NLS-1$
            resultLabel.setText("0 이상의 숫자를 입력해 주세요."); //$NON-NLS-1$
            return;
        }
        Frontend.getInstance().runAction(ActionType.SetUserEnvironmentVariable,
                new EngineConfigValueParameters(key, value), result -> {
                    if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                        resultLabel.setText("수정 완료: " + key); //$NON-NLS-1$
                        keyTextBox.setText(key);
                        queryValue(key, true);
                    } else {
                        resultLabel.setText("수정 실패: " + key); //$NON-NLS-1$
                    }
                });
    }

    private String extractValue(String output) {
        for (String line : output.split("\\r?\\n")) { //$NON-NLS-1$
            String trimmed = line.trim();
            if (trimmed.startsWith("value:")) { //$NON-NLS-1$
                return trimmed.substring("value:".length()).trim(); //$NON-NLS-1$
            }
        }
        return ""; //$NON-NLS-1$
    }

    private String toHtml(String value) {
        return SafeHtmlUtils.fromString(value).asString().replace("\n", "<br/>"); //$NON-NLS-1$ //$NON-NLS-2$
    }
}
