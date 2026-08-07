package org.ovirt.engine.core.common.action;

public class EngineConfigValueParameters extends ActionParametersBase {

    private String key;
    private String value;

    public EngineConfigValueParameters() {
    }

    public EngineConfigValueParameters(String key) {
        this.key = key;
    }

    public EngineConfigValueParameters(String key, String value) {
        this.key = key;
        this.value = value;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
