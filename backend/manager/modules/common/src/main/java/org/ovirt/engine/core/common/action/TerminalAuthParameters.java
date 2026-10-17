/*
 * Copyright 새올정보기술 (OV-Works), 2026
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.core.common.action;

public class TerminalAuthParameters extends ActionParametersBase {
    private static final long serialVersionUID = 1L;

    private String serialNumber;

    public TerminalAuthParameters() {
    }

    public TerminalAuthParameters(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }
}
