/*
 * Copyright 새올정보기술 (OV-Works), 2026
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.core.common.action;

import org.ovirt.engine.core.compat.Guid;

/**
 * Registers, changes or removes a user's dedicated login IP: the one address that user is allowed
 * to log in from. An empty or null {@code dedicatedIp} removes the restriction.
 */
public class SetUserDedicatedIpParameters extends ActionParametersBase {

    private static final long serialVersionUID = 7156320517033401921L;

    private Guid userId;
    private String dedicatedIp;

    public SetUserDedicatedIpParameters() {
    }

    public SetUserDedicatedIpParameters(Guid userId, String dedicatedIp) {
        this.userId = userId;
        this.dedicatedIp = dedicatedIp;
    }

    public Guid getUserId() {
        return userId;
    }

    public void setUserId(Guid userId) {
        this.userId = userId;
    }

    public String getDedicatedIp() {
        return dedicatedIp;
    }

    public void setDedicatedIp(String dedicatedIp) {
        this.dedicatedIp = dedicatedIp;
    }
}
