package org.ovirt.engine.ui.webadmin.section.main.view.popup.configure;

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

    private static final String DEFAULT_KEY = "MAX_FAILURES_SINCE_SUCCESS"; //$NON-NLS-1$
    private static final String INTEGER_TYPE = "class java.lang.Integer"; //$NON-NLS-1$

    interface ViewUiBinder extends UiBinder<Widget, UserEnvironmentVariablesView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    @UiField TextBox keyTextBox;
    @UiField TextBox valueTextBox;
    @UiField Button queryButton;
    @UiField Button updateButton;
    @UiField HTML commandLabel;
    @UiField HTML outputLabel;
    @UiField HTML queriedKeyLabel;
    @UiField HTML typeLabel;
    @UiField HTML descriptionLabel;
    @UiField HTML resultLabel;

    private String queriedKey;

    public UserEnvironmentVariablesView() {
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        queryButton.addClickHandler(event -> querySelectedValue());
        updateButton.addClickHandler(event -> updateValue());
        keyTextBox.setText(DEFAULT_KEY);
        clearQueryResult();
    }

    private void querySelectedValue() {
        String key = keyTextBox.getText() == null ? "" : keyTextBox.getText().trim(); //$NON-NLS-1$
        if (!key.matches("[A-Z][A-Z0-9_]*")) { //$NON-NLS-1$
            resultLabel.setText("올바른 사용자 환경 변수 이름을 입력해 주세요."); //$NON-NLS-1$
            clearQueryResult();
            return;
        }
        queryValue(key);
    }

    private void queryValue(String key) {
        clearQueryResult();
        commandLabel.setText("ovirt-aaa-jdbc-tool settings show --name=" + key); //$NON-NLS-1$
        resultLabel.setText("조회 중: " + key); //$NON-NLS-1$
        queryButton.setEnabled(false);
        Frontend.getInstance().runAction(ActionType.GetUserEnvironmentVariable,
                new EngineConfigValueParameters(key), result -> {
                    queryButton.setEnabled(true);
                    if (result == null || result.getReturnValue() == null || !result.getReturnValue().getSucceeded()) {
                        resultLabel.setText("조회 실패: " + key); //$NON-NLS-1$
                        return;
                    }
                    Object value = result.getReturnValue().getActionReturnValue();
                    String output = value == null ? "" : value.toString(); //$NON-NLS-1$
                    queriedKey = key;
                    queriedKeyLabel.setText(key);
                    valueTextBox.setText(extractField(output, "value:")); //$NON-NLS-1$
                    String type = extractField(output, "type:"); //$NON-NLS-1$
                    typeLabel.setText(type);
                    descriptionLabel.setText(extractField(output, "description:")); //$NON-NLS-1$
                    outputLabel.setHTML(toHtml(output));
                    updateButton.setEnabled(INTEGER_TYPE.equals(type));
                    resultLabel.setText(updateButton.isEnabled()
                            ? "조회 완료 - 값을 수정할 수 있습니다." : "조회 완료 - 읽기 전용 설정입니다."); //$NON-NLS-1$ //$NON-NLS-2$
                }, false);
    }

    private void updateValue() {
        if (queriedKey == null || !updateButton.isEnabled()) {
            resultLabel.setText("수정할 사용자 환경 변수를 먼저 조회해 주세요."); //$NON-NLS-1$
            return;
        }
        String value = valueTextBox.getText().trim();
        if (!value.matches("[0-9]+")) { //$NON-NLS-1$
            resultLabel.setText("0 이상의 숫자를 입력해 주세요."); //$NON-NLS-1$
            return;
        }
        String updatedKey = queriedKey;
        updateButton.setEnabled(false);
        queryButton.setEnabled(false);
        resultLabel.setText("수정 중: " + updatedKey); //$NON-NLS-1$
        Frontend.getInstance().runAction(ActionType.SetUserEnvironmentVariable,
                new EngineConfigValueParameters(updatedKey, value), result -> {
                    if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                        resultLabel.setText("수정 완료: " + updatedKey); //$NON-NLS-1$
                        keyTextBox.setText(updatedKey);
                        queryValue(updatedKey);
                    } else {
                        queryButton.setEnabled(true);
                        updateButton.setEnabled(true);
                        resultLabel.setText("수정 실패: " + updatedKey); //$NON-NLS-1$
                    }
                });
    }

    private String extractField(String output, String fieldName) {
        for (String line : output.split("\\r?\\n")) { //$NON-NLS-1$
            String trimmed = line.trim();
            if (trimmed.startsWith(fieldName)) {
                return trimmed.substring(fieldName.length()).trim();
            }
        }
        return ""; //$NON-NLS-1$
    }

    private void clearQueryResult() {
        queriedKey = null;
        queriedKeyLabel.setText("-"); //$NON-NLS-1$
        typeLabel.setText("-"); //$NON-NLS-1$
        descriptionLabel.setText("-"); //$NON-NLS-1$
        valueTextBox.setText(""); //$NON-NLS-1$
        outputLabel.setText(""); //$NON-NLS-1$
        updateButton.setEnabled(false);
    }

    private String toHtml(String value) {
        return SafeHtmlUtils.fromString(value).asString().replace("\n", "<br/>"); //$NON-NLS-1$ //$NON-NLS-2$
    }
}
