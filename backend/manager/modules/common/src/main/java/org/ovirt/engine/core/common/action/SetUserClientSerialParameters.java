/*
 * Copyright 새올정보기술 (OV-Works), 2026
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.core.common.action;

import org.ovirt.engine.core.compat.Guid;

/**
 * Registers, changes or removes the terminal serial a user logs in with. An empty or null
 * {@code clientSerial} removes it.
 */
public class SetUserClientSerialParameters extends ActionParametersBase {

    private static final long serialVersionUID = 2873405918274630155L;

    private Guid userId;
    private String clientSerial;

    public SetUserClientSerialParameters() {
    }

    public SetUserClientSerialParameters(Guid userId, String clientSerial) {
        this.userId = userId;
        this.clientSerial = clientSerial;
    }

    public Guid getUserId() {
        return userId;
    }

    public void setUserId(Guid userId) {
        this.userId = userId;
    }

    public String getClientSerial() {
        return clientSerial;
    }

    public void setClientSerial(String clientSerial) {
        this.clientSerial = clientSerial;
    }
}
