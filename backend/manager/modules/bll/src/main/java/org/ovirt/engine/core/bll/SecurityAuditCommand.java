package org.ovirt.engine.core.bll;

import java.time.Instant;
import java.time.ZoneId;
import java.util.Collections;
import java.util.List;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.ActionParametersBase;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.common.businessentities.AuditLog;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.AuditLogDao;
import org.ovirt.engine.core.utils.transaction.TransactionSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Command to execute security audit script and log results
 */
public class SecurityAuditCommand<T extends ActionParametersBase> extends CommandBase<T> {

    private static final Logger log = LoggerFactory.getLogger(SecurityAuditCommand.class);

    /** As StartupSecurityAuditManager: every item is recorded, but a runaway audit is capped. */
    static final int MAX_REPORTED_FINDINGS = 200;

    private static final String WEBADMIN = ScheduledVerificationFailureResponse.WEBADMIN;

    @Inject
    private AuditLogDao auditLogDao;

    @Inject
    private ScheduledVerificationFailureResponse failureResponse;

    public SecurityAuditCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected boolean validate() {
        return true;
    }

    @Override
    protected void executeCommand() {
        if (SecurityAuditRunner.isRunning()) {
            reportAlreadyRunning();
            return;
        }
        executeSecurityAudit();
    }

    private void reportAlreadyRunning() {
        String errorMsg = "보안 감사가 이미 실행 중입니다.";
        log.warn("Security audit result: rejected because another audit is running; user='{}'",
                getCurrentUser().getLoginName());
        logAuditEvent(AuditLogType.SECURITY_AUDIT_WARNING, "Security audit request ignored: already running");
        getReturnValue().getExecuteFailedMessages().add(errorMsg);
        setSucceeded(false);
    }

    private void executeSecurityAudit() {
        String userName = getCurrentUser().getLoginName();
        log.info("Security audit requested by user '{}'; runner='{}'", userName, SecurityAuditRunner.RUNNER);
        if (!SecurityAuditRunner.exists()) {
            String errorMsg = "보안 감사 실행기를 찾을 수 없습니다: " + SecurityAuditRunner.RUNNER;
            log.error("Security audit runner not found: {}", SecurityAuditRunner.RUNNER);
            log.error("Security audit result: runner not found; user='{}'", userName);
            logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED,
                    failed("보안 점검 스크립트를 찾을 수 없음 (" + SecurityAuditRunner.RUNNER + ")", userName)); //$NON-NLS-1$ //$NON-NLS-2$
            getReturnValue().getExecuteFailedMessages().add(errorMsg);
            setSucceeded(false);
            return;
        }
        if (!SecurityAuditRunner.isAvailable()) {
            String errorMsg = "보안 감사 실행기를 실행할 수 없습니다: " + SecurityAuditRunner.RUNNER;
            log.error("Security audit runner is not executable: {}", SecurityAuditRunner.RUNNER);
            log.error("Security audit result: runner is not executable; user='{}'", userName);
            logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED,
                    failed("보안 점검 스크립트를 실행할 수 없음 (" + SecurityAuditRunner.RUNNER + ")", userName)); //$NON-NLS-1$ //$NON-NLS-2$
            getReturnValue().getExecuteFailedMessages().add(errorMsg);
            setSucceeded(false);
            return;
        }

        logAuditEvent(AuditLogType.SECURITY_AUDIT_STARTED, "Security audit started");
        log.info("보안검증 실행 시작; user='{}'", userName);
        log.info("Security audit started by user '{}'", userName);

        SecurityAuditRunner.Run run = SecurityAuditRunner.run("security", "webadmin"); //$NON-NLS-1$ //$NON-NLS-2$
        for (String line : run.getOutput().split("\n")) { //$NON-NLS-1$
            log.info("Security Audit: {}", line);
        }
        getReturnValue().setActionReturnValue(run.getOutput());

        switch (run.getOutcome()) {
            case BUSY:
                reportAlreadyRunning();
                return;
            case TIMED_OUT:
                String timeoutMsg = "보안 감사가 " + SecurityAuditRunner.TIMEOUT_MINUTES + "분 내에 완료되지 않았습니다.";
                log.error(timeoutMsg);
                log.error("Security audit result: timed out; user='{}'; timeoutMinutes={}",
                        userName, SecurityAuditRunner.TIMEOUT_MINUTES);
                logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED,
                        failed("보안 점검이 " + SecurityAuditRunner.TIMEOUT_MINUTES + "분 안에 끝나지 않음", userName)); //$NON-NLS-1$ //$NON-NLS-2$
                getReturnValue().getExecuteFailedMessages().add(timeoutMsg);
                setSucceeded(false);
                return;
            case PASSED:
                recordItems(run);
                log.info("보안검증 실행 결과 정상; user='{}'", userName);
                log.info("Security audit result: success; user='{}'; exitCode={}", userName, run.getExitCode());
                logAuditEvent(AuditLogType.SECURITY_AUDIT_COMPLETED, "Security audit completed successfully");
                setSucceeded(true);
                return;
            default:
                String errorMsg = "보안 감사 실패 (종료 코드: " + run.getExitCode() + ")";
                log.error("보안검증 실행 실패; user='{}'; exitCode={}", userName, run.getExitCode());
                log.error("Security audit result: failure; user='{}'; exitCode={}", userName, run.getExitCode());
                List<SecurityAuditRunner.Finding> findings = recordItems(run);
                reportFindings(findings);
                logAuditEvent(AuditLogType.SECURITY_AUDIT_FAILED, failureMessage(findings, run.getExitCode(),
                        userName, Instant.now(), ZoneId.systemDefault()));
                getReturnValue().getExecuteFailedMessages().add(errorMsg);
                setSucceeded(false);
                // As the timer's run: after the failure is recorded, the alert and - unless the
                // policy is NOTIFY - the engine stop after the configured delay.
                String halt = failureResponse.respond(StartupSecurityAuditManager.KIND, WEBADMIN,
                        Instant.now(), "exit code " + run.getExitCode(), userName);
                if (halt != null) {
                    getReturnValue().getExecuteFailedMessages().add(halt);
                }
        }
    }

    /**
     * Puts every item of every process the self-test checked in the audit log - passed, failed,
     * warned about or not applicable - each naming its process and item.
     *
     * @return the items, for the detail of a run that did not pass
     */
    private List<SecurityAuditRunner.Finding> recordItems(SecurityAuditRunner.Run run) {
        List<SecurityAuditRunner.Finding> findings = SecurityAuditRunner.findingsIn(run.getOutput());
        int reported = Math.min(findings.size(), MAX_REPORTED_FINDINGS);
        for (SecurityAuditRunner.Finding finding : findings.subList(0, reported)) {
            VerificationFailureReport.Record record = VerificationFailureReport.selfTestRecord(finding);
            logAuditEvent(record.getType(), record.getMessage());
        }
        if (findings.size() > reported) {
            logAuditEvent(AuditLogType.SECURITY_AUDIT_WARNING,
                    "Security audit reported " + (findings.size() - reported)
                            + " further items; see the self-test log");
        }
        return findings;
    }

    /** {@code 자체시험 실패 : <이유> (관리화면 <사용자>, <시각>)}, for a run that could not be carried out. */
    private static String failed(String reason, String userName) {
        return VerificationFailureReport.selfTestFailed(reason,
                VerificationFailureReport.runContext(WEBADMIN, Instant.now(), userName));
    }

    /**
     * {@code 자체시험 실패 : ovirt-engine/설정 파일 - ... (관리화면 admin, <시각>, 성공·경고·실패 건수, 종료 코드 20)}:
     * the same wording as the engine start's and the timer's run.
     */
    static String failureMessage(List<SecurityAuditRunner.Finding> findings, int exitCode, String userName,
            Instant when, ZoneId zone) {
        return VerificationFailureReport.selfTestFailed(VerificationFailureReport.failureReason(findings, 0),
                VerificationFailureReport.runContext(WEBADMIN, when, userName, zone,
                        VerificationFailureReport.tally(findings), "종료 코드 " + exitCode)); //$NON-NLS-1$
    }

    /** One record with the details of every item that did not pass. */
    private void reportFindings(List<SecurityAuditRunner.Finding> findings) {
        if (SecurityAuditRunner.problemsIn(findings).isEmpty()) {
            return;
        }
        logAuditEvent(AuditLogType.SECURITY_SELF_TEST_FAILURE_DETAIL,
                VerificationFailureReport.selfTestDetail(findings,
                        StartupSecurityAuditManager.summaryContext("webadmin", Instant.now()))); //$NON-NLS-1$
    }

    private void logAuditEvent(AuditLogType type, String message) {
        AuditLog auditLog = new AuditLog(type, type.getSeverity());
        auditLog.setUserId(getCurrentUser().getId());
        auditLog.setUserName(getCurrentUser().getLoginName());
        auditLog.setMessage(message);
        auditLog.setCustomData(message);
        TransactionSupport.executeInNewTransaction(() -> {
            auditLogDao.save(auditLog);
            return null;
        });
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(Guid.SYSTEM,
                VdcObjectType.System,
                ActionGroup.AUDIT_LOG_MANAGEMENT));
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        // A run that did not pass has already said why, as "자체시험 실패 : <이유>"; a second
        // record with no reason in it would only stand next to it in the event list.
        return getSucceeded() ? AuditLogType.SECURITY_AUDIT_COMPLETED : AuditLogType.UNASSIGNED;
    }
}
