package org.ovirt.engine.core.common.businessentities;

import java.io.Serializable;

public class EngineConfigEntry implements Serializable {
    private static final long serialVersionUID = 1L;

    private String name;
    private String description;
    private String value;

    public EngineConfigEntry() {
    }

    public EngineConfigEntry(String name, String description, String value) {
        this.name = name;
        this.description = description;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
