package org.ovirt.engine.core.bll;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.enterprise.concurrent.ManagedScheduledExecutorService;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.ovirt.engine.core.bll.interfaces.BackendInternal;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.BackendService;
import org.ovirt.engine.core.common.action.ActionReturnValue;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.ExecuteVmGuestCommandParameters;
import org.ovirt.engine.core.common.businessentities.VM;
import org.ovirt.engine.core.common.businessentities.VMStatus;
import org.ovirt.engine.core.common.businessentities.VmGuestEventMark;
import org.ovirt.engine.core.common.config.Config;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.common.osinfo.OsRepository;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogableImpl;
import org.ovirt.engine.core.dao.VmDao;
import org.ovirt.engine.core.dao.VmGuestEventMarkDao;
import org.ovirt.engine.core.utils.threadpool.ThreadPools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Puts what has gone seriously wrong inside a guest into the engine's event list.
 *
 * <p>A guest keeps its own account of its faults and nobody outside it ever reads that account. A
 * disk failing, a service that will not start, a machine bugchecking and coming back - all of it is
 * in the guest's event log and none of it reaches the people watching the engine, who find out when
 * somebody tells them. This asks each running Windows VM what it has recorded at Critical and Error
 * and writes those into the event list, where the rest of the estate's faults already are.</p>
 *
 * <p>Only Critical and Error from the logs that grade themselves. The list the security dialog
 * shows is everything the guest logged, which on a quiet machine is mostly this engine asking it
 * things; putting that in the event list would bury what the event list is for.</p>
 *
 * <p>The security log grades nothing - it records a refused logon and an erased audit trail alike
 * as informational - so it is read by what its entries are rather than by what they claim to be
 * worth: failed audits, and the successful entries that change the audit trail or the accounts.
 * Those are an audit trail rather than a fault report, so {@code VmGuestSecurityEventsEnabled}
 * turns them on and off on their own.</p>
 *
 * <p>Asking is not cheap. It goes to the host over SSH and from there through the guest agent, so a
 * pass asks a limited number of VMs and the next pass carries on from where it left off. Every VM
 * is reached; no single pass is long. On an estate too large for that to keep up,
 * {@code VmGuestCriticalEventsIntervalMinutes} and {@code VmGuestCriticalEventsVmsPerPass} are what
 * to change, and {@code VmGuestCriticalEventsEnabled} is what stops it asking at all.</p>
 *
 * <p>Each event is recorded once. The guest numbers the entries in each of its logs and the numbers
 * only go up, so the highest one seen is remembered per VM and per log and anything at or below it
 * has been recorded already. A guest whose log was cleared starts numbering again, which reads as a
 * number far below what was remembered - that is taken as a new log rather than as old events, and
 * the mark is moved back. The marks are kept in the database: held in memory, a restart of the
 * engine would report again everything the lookback window still holds.</p>
 */
@Singleton
public class GuestCriticalEventAuditManager implements BackendService {

    private static final Logger log = LoggerFactory.getLogger(GuestCriticalEventAuditManager.class);

    /** A moment for the engine to finish coming up before it starts asking VMs anything. */
    private static final long START_DELAY_MINUTES = 5;

    /**
     * How many of one VM's events one pass records.
     *
     * <p>A guest in a loop - a driver failing every few seconds - would otherwise fill the event
     * list with one fault. What is left is not recorded: the next pass starts above it, so a burst
     * is represented by its first entries rather than by all of them.
     */
    private static final int MAX_EVENTS_PER_VM = 20;

    /** How far below the remembered mark a number has to fall to be read as a cleared log. */
    private static final long CLEARED_LOG_MARGIN = 1000;

    /** The one guest log whose entries are an audit trail rather than a fault report. */
    static final String SECURITY_LOG = "Security"; //$NON-NLS-1$

    /**
     * The security entries that say the audit trail itself was interfered with. Windows records
     * both as ordinary successful operations, so nothing in the entry says how serious it is.
     */
    private static final Set<String> AUDIT_TRAIL_EVENT_IDS = Set.of(
            "1102", // the security log was cleared //$NON-NLS-1$
            "4719"); // the system audit policy was changed //$NON-NLS-1$

    /** How the time a guest stamped on an entry is written into an engine event. */
    private static final DateTimeFormatter EVENT_TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC); //$NON-NLS-1$

    @Inject
    @ThreadPools(ThreadPools.ThreadPoolType.EngineScheduledThreadPool)
    private ManagedScheduledExecutorService executor;

    @Inject
    private BackendInternal backend;

    @Inject
    private VmDao vmDao;

    @Inject
    private OsRepository osRepository;

    @Inject
    private AuditLogDirector auditLogDirector;

    @Inject
    private VmGuestEventMarkDao markDao;

    /** Where the last pass stopped, so the next one carries on rather than starting over. */
    private Guid resumeAfter;

    @PostConstruct
    private void init() {
        log.info("Start initializing {}", getClass().getSimpleName());
        long interval = Math.max(1, Config.<Integer> getValue(
                ConfigValues.VmGuestCriticalEventsIntervalMinutes));
        executor.scheduleWithFixedDelay(this::collect,
                START_DELAY_MINUTES,
                interval,
                TimeUnit.MINUTES);
        log.info("Finished initializing {}", getClass().getSimpleName());
    }

    void collect() {
        try {
            if (!Config.<Boolean> getValue(ConfigValues.VmGuestCriticalEventsEnabled)) {
                return;
            }
            for (VM vm : nextToAsk(candidates())) {
                ask(vm);
            }
        } catch (Throwable t) {
            // The next pass asks the same VMs; a pass that failed loses nothing, and it must not
            // take the scheduled task down with it.
            log.error("Exception in collecting guest events: {}", ExceptionUtils.getRootCauseMessage(t));
            log.debug("Exception", t);
        }
    }

    /** The VMs worth asking: up, on a host, and running something that keeps a Windows event log. */
    private List<VM> candidates() {
        List<VM> candidates = new ArrayList<>();
        for (VM vm : vmDao.getAll()) {
            if (vm.getStatus() == VMStatus.Up
                    && vm.getRunOnVds() != null
                    && osRepository.isWindows(vm.getOs())) {
                candidates.add(vm);
            }
        }
        candidates.sort((left, right) -> left.getId().compareTo(right.getId()));
        return candidates;
    }

    /**
     * The next few, carrying on from where the last pass stopped.
     *
     * <p>In a fixed order and from where the last one ended, so that every VM comes round rather
     * than the first few being asked over and over while the rest are never asked at all.</p>
     */
    List<VM> nextToAsk(List<VM> candidates) {
        if (candidates.isEmpty()) {
            return Collections.emptyList();
        }
        int perPass = Math.max(1, Config.<Integer> getValue(ConfigValues.VmGuestCriticalEventsVmsPerPass));
        int from = 0;
        if (resumeAfter != null) {
            for (int i = 0; i < candidates.size(); i++) {
                if (candidates.get(i).getId().compareTo(resumeAfter) > 0) {
                    from = i;
                    break;
                }
                from = i + 1;
            }
        }
        List<VM> asking = new ArrayList<>();
        for (int i = 0; i < Math.min(perPass, candidates.size()); i++) {
            asking.add(candidates.get((from + i) % candidates.size()));
        }
        resumeAfter = asking.get(asking.size() - 1).getId();
        return asking;
    }

    private void ask(VM vm) {
        String output;
        try {
            ExecuteVmGuestCommandParameters parameters = new ExecuteVmGuestCommandParameters();
            parameters.setVmId(vm.getId());
            parameters.setCriticalEventsRequested(true);
            parameters.setLookbackHours(Config.<Integer> getValue(
                    ConfigValues.VmGuestCriticalEventsLookbackHours));
            parameters.setSecurityEventsRequested(
                    Config.<Boolean> getValue(ConfigValues.VmGuestSecurityEventsEnabled));
            ActionReturnValue result = backend.runInternalAction(ActionType.ExecuteVmGuestCommand, parameters);
            if (result == null || !result.getSucceeded() || result.getActionReturnValue() == null) {
                reportUnreadable(vm, reason(result));
                return;
            }
            output = result.getActionReturnValue().toString();
        } catch (RuntimeException e) {
            log.debug("Unable to ask VM {} what has gone wrong inside it: {}", vm.getName(), e.getMessage());
            reportUnreadable(vm, e.getMessage());
            return;
        }
        record(vm, output);
    }

    /**
     * Says that a guest could not be read, but only of one that has been read before.
     *
     * <p>A guest with no agent, a host that cannot be reached, a VM that went down between the
     * list and the asking: ordinary, and an estate full of machines that never answer would report
     * the same nothing every pass. One that used to answer and has stopped is the other thing
     * entirely - its audit trail has gone quiet and nobody would know - so that one is said aloud,
     * once an hour at most.</p>
     */
    private void reportUnreadable(VM vm, String reason) {
        try {
            if (markDao.getByVmId(vm.getId()).isEmpty()) {
                return;
            }
            AuditLogable auditable = new AuditLogableImpl();
            auditable.setVmId(vm.getId());
            auditable.setVmName(vm.getName());
            auditable.setVdsId(vm.getRunOnVds());
            auditable.setVdsName(vm.getRunOnVdsName());
            auditable.addCustomValue("Reason", StringUtils.isBlank(reason) //$NON-NLS-1$
                    ? "no reason was reported" : reason); //$NON-NLS-1$
            auditLogDirector.log(auditable, AuditLogType.VM_GUEST_EVENT_COLLECTION_FAILED);
        } catch (RuntimeException e) {
            log.error("Unable to report that VM {} could not be read: {}", vm.getName(), e.getMessage());
            log.debug("Exception", e);
        }
    }

    private static String reason(ActionReturnValue result) {
        if (result == null) {
            return null;
        }
        List<String> messages = result.getExecuteFailedMessages();
        if (messages != null && !messages.isEmpty()) {
            return String.join("; ", messages); //$NON-NLS-1$
        }
        return result.getActionReturnValue() == null ? null : result.getActionReturnValue().toString();
    }

    /** Package private so the one rule that matters - recorded once - can be exercised. */
    void record(VM vm, String output) {
        Map<String, Long> marks = marksOf(vm);
        Map<String, Long> moved = new LinkedHashMap<>();
        int recordedNow = 0;
        for (String line : output.split("\n")) { //$NON-NLS-1$
            GuestEvent event = GuestEvent.parse(line);
            if (event == null) {
                continue;
            }
            Long mark = marks.get(event.log);
            if (mark != null && event.recordId <= mark && event.recordId > mark - CLEARED_LOG_MARGIN) {
                continue;
            }
            if (recordedNow >= MAX_EVENTS_PER_VM) {
                // The rest wait. The mark stays where it is, so the next pass starts here.
                break;
            }
            audit(vm, event);
            marks.put(event.log, event.recordId);
            moved.put(event.log, event.recordId);
            recordedNow++;
        }
        for (Map.Entry<String, Long> entry : moved.entrySet()) {
            markDao.save(new VmGuestEventMark(vm.getId(), entry.getKey(), entry.getValue()));
        }
    }

    /** Where this VM was left, per log. */
    private Map<String, Long> marksOf(VM vm) {
        Map<String, Long> marks = new LinkedHashMap<>();
        for (VmGuestEventMark mark : markDao.getByVmId(vm.getId())) {
            marks.put(mark.getLogName(), mark.getLastRecordId());
        }
        return marks;
    }

    private void audit(VM vm, GuestEvent event) {
        try {
            AuditLogable auditable = new AuditLogableImpl();
            auditable.setVmId(vm.getId());
            auditable.setVmName(vm.getName());
            auditable.setVdsId(vm.getRunOnVds());
            auditable.addCustomValue("GuestLevel", levelName(event.level)); //$NON-NLS-1$
            auditable.addCustomValue("GuestLog", event.log); //$NON-NLS-1$
            auditable.addCustomValue("GuestSource", event.source); //$NON-NLS-1$
            auditable.addCustomValue("GuestEventId", event.eventId); //$NON-NLS-1$
            auditable.addCustomValue("GuestTime", eventTime(event.time)); //$NON-NLS-1$
            auditable.addCustomValue("GuestMessage", event.message); //$NON-NLS-1$
            auditLogDirector.log(auditable, classify(event));
        } catch (RuntimeException e) {
            log.error("Unable to record a guest event of VM {}: {}", vm.getName(), e.getMessage());
            log.debug("Exception", e);
        }
    }

    /**
     * What the entry is recorded as. The security log is judged by what its entry is rather than
     * by the level it carries: it records a refused logon and an erased audit trail alike as
     * informational, so the level there says nothing at all.
     */
    static AuditLogType classify(GuestEvent event) {
        if (!SECURITY_LOG.equals(event.log)) {
            return AuditLogType.VM_GUEST_CRITICAL_EVENT;
        }
        return AUDIT_TRAIL_EVENT_IDS.contains(event.eventId)
                ? AuditLogType.VM_GUEST_AUDIT_TRAIL_EVENT
                : AuditLogType.VM_GUEST_SECURITY_EVENT;
    }

    /**
     * The name of a level, in the language of the engine.
     *
     * <p>The guest knows one too and will not say it in a language the engine reads: the display
     * name of a level is translated, so a Korean guest calls Error something an English one does
     * not. The number is the same everywhere, and the name for it is put on here.</p>
     */
    static String levelName(String level) {
        switch (level) {
            case "1": //$NON-NLS-1$
                return "Critical"; //$NON-NLS-1$
            case "2": //$NON-NLS-1$
                return "Error"; //$NON-NLS-1$
            case "3": //$NON-NLS-1$
                return "Warning"; //$NON-NLS-1$
            case "0": //$NON-NLS-1$
            case "4": //$NON-NLS-1$
                return "Information"; //$NON-NLS-1$
            case "5": //$NON-NLS-1$
                return "Verbose"; //$NON-NLS-1$
            default:
                return "Level " + level; //$NON-NLS-1$
        }
    }

    /**
     * The moment the guest stamped on the entry, written the way the rest of the engine writes a
     * time. The guest hands it over in UTC in the round trip format, which is the same in every
     * locale and calendar; anything else it hands over is passed on as it came.
     */
    static String eventTime(String time) {
        try {
            return EVENT_TIME_FORMAT.format(Instant.parse(time.trim()));
        } catch (RuntimeException e) {
            return time;
        }
    }

    /** One line of what the guest handed back. */
    static class GuestEvent {

        /** Record number, log, level, source, event id, time, message. */
        private static final int FIELDS = 7;

        final long recordId;
        final String log;
        final String level;
        final String source;
        final String eventId;
        final String time;
        final String message;

        private GuestEvent(String[] fields) {
            this.recordId = Long.parseLong(fields[0].trim());
            this.log = fields[1];
            this.level = fields[2];
            this.source = fields[3];
            this.eventId = fields[4];
            this.time = fields[5];
            this.message = fields[6];
        }

        /**
         * @return what the line says, or null when it does not say it
         *
         * <p>Null rather than an exception: the output is whatever a guest's PowerShell wrote, and
         * one line it wrote oddly is not a reason to drop the rest of what it said.</p>
         */
        static GuestEvent parse(String line) {
            if (StringUtils.isBlank(line)) {
                return null;
            }
            String[] fields = line.trim().split("\t", FIELDS); //$NON-NLS-1$
            if (fields.length != FIELDS) {
                return null;
            }
            try {
                return new GuestEvent(fields);
            } catch (NumberFormatException e) {
                return null;
            }
        }
    }
}
