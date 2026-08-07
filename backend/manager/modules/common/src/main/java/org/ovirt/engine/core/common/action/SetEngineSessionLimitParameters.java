package org.ovirt.engine.core.common.action;

public class SetEngineSessionLimitParameters extends ActionParametersBase {

    private static final long serialVersionUID = -4481070682556918753L;

    private int sessionLimit;

    public SetEngineSessionLimitParameters() {
    }

    public SetEngineSessionLimitParameters(int sessionLimit) {
        this.sessionLimit = sessionLimit;
    }

    public int getSessionLimit() {
        return sessionLimit;
    }

    public void setSessionLimit(int sessionLimit) {
        this.sessionLimit = sessionLimit;
    }
}
