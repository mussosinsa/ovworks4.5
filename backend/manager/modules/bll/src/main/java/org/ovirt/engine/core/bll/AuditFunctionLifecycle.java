/*
 * Copyright 새올정보기술 (OV-Works), 2026
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.core.bll;

import java.util.concurrent.atomic.AtomicBoolean;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogableImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Records the start and the end of the audit function in the event list: "감사기능 시작" when the
 * engine service comes up and "감사기능 종료" when it goes down.
 *
 * <p>Each is recorded once per run of the service. The end is recorded however the run ends while
 * the engine can still write - a stop, a halt by the security verification, or an initialization
 * that failed after the start was recorded - so that a start in the event list is always closed
 * by an end, and a start with no end after it means the service did not get to stop (killed,
 * crashed or the host lost).</p>
 */
@Singleton
public class AuditFunctionLifecycle {

    private static final Logger log = LoggerFactory.getLogger(AuditFunctionLifecycle.class);

    static final String REASON_STARTED = "엔진 서비스 시작"; //$NON-NLS-1$
    static final String REASON_STOPPED = "엔진 서비스 중지"; //$NON-NLS-1$
    static final String REASON_INITIALIZATION_FAILED = "엔진 서비스 초기화 실패"; //$NON-NLS-1$

    /**
     * The engine version the records name: the product's display version, the one the About dialog
     * and the welcome page show (OV-Works Engine 4.5.7-1.el9), not the package version engine-setup
     * stores as ProductRPMVersion.
     */
    public static final String DISPLAY_ENGINE_VERSION = "4.5.7-1.el9"; //$NON-NLS-1$

    private final AtomicBoolean running = new AtomicBoolean();

    @Inject
    private AuditLogDirector auditLogDirector;

    /** Records "감사기능 시작", once, however often the engine's initialization is entered. */
    public void started(String engineVersion) {
        if (running.compareAndSet(false, true)) {
            log.info("감사기능 시작; 엔진 버전='{}'", engineVersion);
            write(event(engineVersion, REASON_STARTED), AuditLogType.AUDIT_FUNCTION_STARTED);
        }
    }

    /** Records "감사기능 종료", once, and only after a start was recorded. */
    public void stopped(String engineVersion, String reason) {
        if (running.compareAndSet(true, false)) {
            log.info("감사기능 종료; 엔진 버전='{}'; 사유='{}'", engineVersion, reason);
            write(event(engineVersion, reason), AuditLogType.AUDIT_FUNCTION_STOPPED);
        }
    }

    boolean isRunning() {
        return running.get();
    }

    static AuditLogable event(String engineVersion, String reason) {
        AuditLogable event = new AuditLogableImpl();
        event.addCustomValue("EngineVersion", StringUtils.defaultIfEmpty(engineVersion, "UNKNOWN")); //$NON-NLS-1$ //$NON-NLS-2$
        event.addCustomValue("Reason", reason); //$NON-NLS-1$
        return event;
    }

    /**
     * A record that cannot be written must not keep the engine from starting or stopping; what
     * went wrong is in engine.log.
     */
    private void write(AuditLogable event, AuditLogType type) {
        try {
            record(event, type);
        } catch (RuntimeException e) {
            log.error("감사기능 {} 기록 실패: {}", type, e.getMessage());
            log.debug("Exception", e);
        }
    }

    /** Overridable so that a test can see what is recorded. */
    protected void record(AuditLogable event, AuditLogType type) {
        auditLogDirector.log(event, type);
    }
}
