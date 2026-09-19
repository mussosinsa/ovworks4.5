package org.ovirt.engine.core.bll;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
import org.ovirt.engine.core.common.config.Config;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.common.osinfo.OsRepository;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogableImpl;
import org.ovirt.engine.core.dao.VmDao;
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
 * <p>Only Critical and Error. The list the security dialog shows is everything the guest logged,
 * which on a quiet machine is mostly this engine asking it things; putting that in the event list
 * would bury what the event list is for.</p>
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
 * the mark is moved back.</p>
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

    /** The highest record number already recorded, per VM and per guest log. */
    private final Map<Guid, Map<String, Long>> recorded = new HashMap<>();

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
            List<VM> candidates = candidates();
            forget(candidates);
            for (VM vm : nextToAsk(candidates)) {
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

    /** Lets go of what was remembered about VMs that are no longer running. */
    private void forget(List<VM> candidates) {
        List<Guid> running = new ArrayList<>();
        for (VM vm : candidates) {
            running.add(vm.getId());
        }
        recorded.keySet().retainAll(running);
    }

    private void ask(VM vm) {
        String output;
        try {
            ExecuteVmGuestCommandParameters parameters = new ExecuteVmGuestCommandParameters();
            parameters.setVmId(vm.getId());
            parameters.setCriticalEventsRequested(true);
            parameters.setLookbackHours(Config.<Integer> getValue(
                    ConfigValues.VmGuestCriticalEventsLookbackHours));
            ActionReturnValue result = backend.runInternalAction(ActionType.ExecuteVmGuestCommand, parameters);
            if (result == null || !result.getSucceeded() || result.getActionReturnValue() == null) {
                // A guest with no agent, a host that cannot be reached, a VM that went down
                // between the list and the asking. Ordinary, and not worth an event of its own.
                return;
            }
            output = result.getActionReturnValue().toString();
        } catch (RuntimeException e) {
            log.debug("Unable to ask VM {} what has gone wrong inside it: {}", vm.getName(), e.getMessage());
            return;
        }
        record(vm, output);
    }

    /** Package private so the one rule that matters - recorded once - can be exercised. */
    void record(VM vm, String output) {
        Map<String, Long> marks = recorded.computeIfAbsent(vm.getId(), id -> new LinkedHashMap<>());
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
            recordedNow++;
        }
    }

    private void audit(VM vm, GuestEvent event) {
        try {
            AuditLogable auditable = new AuditLogableImpl();
            auditable.setVmId(vm.getId());
            auditable.setVmName(vm.getName());
            auditable.setVdsId(vm.getRunOnVds());
            auditable.addCustomValue("GuestLevel", event.level); //$NON-NLS-1$
            auditable.addCustomValue("GuestLog", event.log); //$NON-NLS-1$
            auditable.addCustomValue("GuestSource", event.source); //$NON-NLS-1$
            auditable.addCustomValue("GuestEventId", event.eventId); //$NON-NLS-1$
            auditable.addCustomValue("GuestTime", event.time); //$NON-NLS-1$
            auditable.addCustomValue("GuestMessage", event.message); //$NON-NLS-1$
            auditLogDirector.log(auditable, AuditLogType.VM_GUEST_CRITICAL_EVENT);
        } catch (RuntimeException e) {
            log.error("Unable to record a guest event of VM {}: {}", vm.getName(), e.getMessage());
            log.debug("Exception", e);
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
