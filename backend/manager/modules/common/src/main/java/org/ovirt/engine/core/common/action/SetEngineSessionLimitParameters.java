package org.ovirt.engine.core.common.action;

import org.ovirt.engine.core.compat.Guid;

public class SetEngineSessionLimitParameters extends ActionParametersBase {

    private static final long serialVersionUID = -4481070682556918753L;

    private int sessionLimit;
    private Guid userId;

    public SetEngineSessionLimitParameters() {
    }

    public SetEngineSessionLimitParameters(Guid userId, int sessionLimit) {
        this.userId = userId;
        this.sessionLimit = sessionLimit;
    }

    public Guid getUserId() {
        return userId;
    }

    public void setUserId(Guid userId) {
        this.userId = userId;
    }

    public int getSessionLimit() {
        return sessionLimit;
    }

    public void setSessionLimit(int sessionLimit) {
        this.sessionLimit = sessionLimit;
    }
}
