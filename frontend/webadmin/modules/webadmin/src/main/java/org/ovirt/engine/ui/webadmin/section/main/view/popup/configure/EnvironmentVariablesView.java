package org.ovirt.engine.ui.webadmin.section.main.view.popup.configure;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.gwtbootstrap3.client.ui.Button;
import org.ovirt.engine.core.common.action.ActionParametersBase;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.EngineConfigValueParameters;
import org.ovirt.engine.ui.frontend.Frontend;
import org.ovirt.engine.ui.uicommonweb.ErrorPopupManager;
import org.ovirt.engine.ui.uicommonweb.TypeResolver;
import org.ovirt.engine.ui.uicompat.FrontendActionAsyncResult;

import com.google.gwt.core.client.GWT;
import com.google.gwt.safehtml.shared.SafeHtmlUtils;
import com.google.gwt.uibinder.client.UiBinder;
import com.google.gwt.uibinder.client.UiField;
import com.google.gwt.user.client.ui.Composite;
import com.google.gwt.user.client.ui.HTML;
import com.google.gwt.user.client.ui.Label;
import com.google.gwt.user.client.ui.TextBox;
import com.google.gwt.user.client.ui.Widget;

public class EnvironmentVariablesView extends Composite {

    interface ViewUiBinder extends UiBinder<Widget, EnvironmentVariablesView> {
        ViewUiBinder uiBinder = GWT.create(ViewUiBinder.class);
    }

    @UiField
    Button queryButton;

    @UiField
    Button updateButton;

    @UiField
    TextBox keyTextBox;

    @UiField
    TextBox valueTextBox;

    @UiField
    HTML resultLabel;

    @UiField
    Label queriedKeyLabel;

    @UiField
    Label queriedDescriptionLabel;

    private String lastQueriedKey;
    private final Map<String, String> descriptionsByKey = new HashMap<>();

    public EnvironmentVariablesView() {
        initWidget(ViewUiBinder.uiBinder.createAndBindUi(this));
        initHandlers();
        loadDescriptions();
        clearQueriedState();
        resultLabel.setText("변수 이름을 입력한 뒤 조회해 주세요."); //$NON-NLS-1$
    }

    private void initHandlers() {
        queryButton.addClickHandler(event -> queryValue());
        updateButton.addClickHandler(event -> updateValue());

        keyTextBox.addValueChangeHandler(event -> clearQueriedState());
        keyTextBox.addKeyUpHandler(event -> clearQueriedState());
    }

    private void loadDescriptions() {
        Frontend.getInstance().runAction(ActionType.ListEngineConfigProperties, new ActionParametersBase(), result -> {
            if (result == null || result.getReturnValue() == null || !result.getReturnValue().getSucceeded()) {
                return;
            }
            Object payload = result.getReturnValue().getActionReturnValue();
            if (!(payload instanceof List<?>)) {
                return;
            }
            descriptionsByKey.clear();
            for (Object row : (List<?>) payload) {
                if (row == null) {
                    continue;
                }
                String[] parts = row.toString().split("\\t", 2); //$NON-NLS-1$
                if (parts.length > 0) {
                    String key = parts[0].trim();
                    String description = parts.length > 1 ? parts[1].trim() : ""; //$NON-NLS-1$
                    descriptionsByKey.put(key, description);
                }
            }
        });
    }

    private void queryValue() {
        clearQueriedState();
        String key = keyTextBox.getText() != null ? keyTextBox.getText().trim() : ""; //$NON-NLS-1$
        if (key.isEmpty()) {
            resultLabel.setText("키를 입력해 주세요."); //$NON-NLS-1$
            return;
        }

        if (!descriptionsByKey.isEmpty() && !descriptionsByKey.containsKey(key)) {
            showMissingVariablePopup();
            resultLabel.setText("존재하지 않는 변수입니다. 다시확인하세요"); //$NON-NLS-1$
            return;
        }

        resultLabel.setText("Engine 런타임 구성값 조회 중..."); //$NON-NLS-1$
        Frontend.getInstance().runAction(ActionType.GetEngineConfigValue, new EngineConfigValueParameters(key),
                result -> handleEngineConfigResult(result, false), false);
    }

    private void updateValue() {
        String key = keyTextBox.getText() != null ? keyTextBox.getText().trim() : ""; //$NON-NLS-1$
        if (key.isEmpty()) {
            resultLabel.setText("키를 입력해 주세요."); //$NON-NLS-1$
            return;
        }

        if (lastQueriedKey == null || !key.equals(lastQueriedKey)) {
            resultLabel.setText("먼저 조회 후 수정해 주세요."); //$NON-NLS-1$
            return;
        }

        String value = valueTextBox.getText() == null ? "" : valueTextBox.getText(); //$NON-NLS-1$
        resultLabel.setText("engine-config -s 수정 중..."); //$NON-NLS-1$
        Frontend.getInstance().runAction(ActionType.SetEngineConfigValue, new EngineConfigValueParameters(key, value),
                result -> {
                    handleEngineConfigResult(result, true);
                    if (result != null && result.getReturnValue() != null && result.getReturnValue().getSucceeded()) {
                        queryValue();
                    }
                });
    }

    private void handleEngineConfigResult(FrontendActionAsyncResult result, boolean isUpdate) {
        String defaultError = isUpdate ? "수정 실패" : "조회 실패"; //$NON-NLS-1$ //$NON-NLS-2$
        if (result != null && result.getReturnValue() != null) {
            Object output = result.getReturnValue().getActionReturnValue();
            if (result.getReturnValue().getSucceeded()) {
                String text = output instanceof String ? (String) output : (isUpdate ? "수정 완료" : "조회 완료"); //$NON-NLS-1$ //$NON-NLS-2$
                if (!isUpdate && output instanceof String) {
                    String key = keyTextBox.getText().trim();
                    String currentValue = extractEngineConfigValue((String) output, key);
                    valueTextBox.setValue(currentValue);
                    queriedKeyLabel.setText(key + ":"); //$NON-NLS-1$
                    queriedDescriptionLabel.setText(descriptionsByKey.getOrDefault(key, "")); //$NON-NLS-1$
                    lastQueriedKey = key;
                    updateButton.setEnabled(true);
                }
                resultLabel.setHTML(SafeHtmlUtils.fromString(text).asString().replace("\n", "<br/>")); //$NON-NLS-1$ //$NON-NLS-2$
                return;
            }
            if (output instanceof String && !((String) output).isEmpty()) {
                String outputText = (String) output;
                if (!isUpdate && isMissingEngineConfigKeyError(outputText)) {
                    showMissingVariablePopup();
                    resultLabel.setText("존재하지 않는 변수입니다. 다시확인하세요"); //$NON-NLS-1$
                    return;
                }
                resultLabel.setHTML(SafeHtmlUtils.fromString(outputText).asString().replace("\n", "<br/>")); //$NON-NLS-1$ //$NON-NLS-2$
                return;
            }
        }
        resultLabel.setText(defaultError);
    }


    private void showMissingVariablePopup() {
        ErrorPopupManager popupManager =
                (ErrorPopupManager) TypeResolver.getInstance().resolve(ErrorPopupManager.class);
        if (popupManager != null) {
            popupManager.show("존재하지 않는 변수입니다. 다시확인하세요"); //$NON-NLS-1$
        }
    }

    private boolean isMissingEngineConfigKeyError(String output) {
        String normalized = output == null ? "" : output.toLowerCase(); //$NON-NLS-1$
        return normalized.contains("no such") //$NON-NLS-1$
                || normalized.contains("not found") //$NON-NLS-1$
                || normalized.contains("does not exist") //$NON-NLS-1$
                || normalized.contains("doesn't exist") //$NON-NLS-1$
                || normalized.contains("there is no variable") //$NON-NLS-1$
                || normalized.contains("no variable named"); //$NON-NLS-1$
    }

    private void clearQueriedState() {
        lastQueriedKey = null;
        queriedKeyLabel.setText("-"); //$NON-NLS-1$
        queriedDescriptionLabel.setText("-"); //$NON-NLS-1$
        valueTextBox.setText(""); //$NON-NLS-1$
        updateButton.setEnabled(false);
    }

    private String extractEngineConfigValue(String output, String key) {
        String[] lines = output.split("\\r?\\n"); //$NON-NLS-1$
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (trimmed.startsWith(key + ":")) { //$NON-NLS-1$
                return normalizeEngineConfigValue(trimmed.substring(key.length() + 1).trim());
            }
            if (trimmed.startsWith(key + "=")) { //$NON-NLS-1$
                return normalizeEngineConfigValue(trimmed.substring(key.length() + 1).trim());
            }
        }
        return output.trim();
    }

    private String normalizeEngineConfigValue(String value) {
        int versionIdx = value.indexOf(" version:"); //$NON-NLS-1$
        if (versionIdx >= 0) {
            return value.substring(0, versionIdx).trim();
        }
        return value;
    }
}
