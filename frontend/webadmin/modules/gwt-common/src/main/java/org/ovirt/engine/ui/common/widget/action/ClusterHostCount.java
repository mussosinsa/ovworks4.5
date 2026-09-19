package org.ovirt.engine.ui.common.widget.action;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.ui.frontend.AsyncQuery;
import org.ovirt.engine.ui.uicommonweb.dataprovider.AsyncDataProvider;

/**
 * How many hosts a cluster has, as far as this browser knows.
 *
 * <p>Nothing the administration application already holds says how large a cluster is - a virtual
 * machine carries the cluster it is in, not the size of it - so the answer has to be asked for, and
 * asking takes a moment. Kept here so the asking happens once per cluster rather than once per
 * redraw of a button, and so an answer is let go of often enough that a host added to a cluster is
 * noticed without a reload.</p>
 *
 * <p>Whoever asks is told when the answer arrives, because by then the button that asked has
 * already been drawn.</p>
 */
public class ClusterHostCount {

    /**
     * How long an answer is kept, in milliseconds.
     *
     * <p>Long enough that selecting one machine after another does not ask again for each, short
     * enough that adding a host to a cluster shows up in about the time it takes to notice that it
     * has not. It is also how long an unanswered question is waited for: a query that fails calls
     * nobody back, and a button greyed out by a question nobody will ever answer would stay grey
     * for as long as the tab is open.</p>
     */
    static final int FORGET_AFTER_MILLIS = 30 * 1000;

    /** What a cluster nobody could count is taken as having: enough, and let the engine decide. */
    static final int UNCOUNTABLE = Integer.MAX_VALUE;

    /** What a minimum nobody could read is taken as being: one, which restricts nothing. */
    static final int NO_RESTRICTION = 1;

    /** The clock, so a test can say what time it is. */
    static LongSupplier clock = System::currentTimeMillis;

    private static final Map<Guid, Answer> perCluster = new HashMap<>();

    private ClusterHostCount() {
    }

    /**
     * @param clusterId the cluster a virtual machine is in
     * @param whenTheAnswerArrives run once the count is known, if it is not known yet. The same
     *        object each time from the same caller, so that a caller which asks on every redraw
     *        is told once rather than once per redraw
     * @return whether the cluster has as many hosts as a migration within it needs, or {@code null}
     *         while that is still being asked
     */
    public static Boolean enoughToMigrateWithin(Guid clusterId, Runnable whenTheAnswerArrives) {
        int needed = howManyAreNeeded();
        if (needed <= NO_RESTRICTION) {
            return Boolean.TRUE;
        }
        Integer hosts = hosts(clusterId, whenTheAnswerArrives);
        return hosts == null ? null : Boolean.valueOf(hosts >= needed);
    }

    /** Lets go of everything counted so far, so the next question is asked afresh. */
    static void forget() {
        perCluster.clear();
    }

    /**
     * @return what the engine's MinimumHostsForMigration says, or one if it has not been read
     *
     * <p>Every option is already in this browser, fetched in one query when the session began, so
     * this needs no query of its own. One if it is somehow missing: the engine holds the same rule
     * and will refuse the migration itself, and a button greyed out over a value that could not be
     * read would be a restriction nobody could lift.</p>
     */
    private static int howManyAreNeeded() {
        Object configured = AsyncDataProvider.getInstance()
                .getConfigValuePreConverted(ConfigValues.MinimumHostsForMigration);
        return configured instanceof Integer ? ((Integer) configured).intValue() : NO_RESTRICTION;
    }

    private static Integer hosts(Guid clusterId, Runnable whenTheAnswerArrives) {
        if (clusterId == null) {
            return Integer.valueOf(UNCOUNTABLE);
        }
        Answer counted = perCluster.get(clusterId);
        if (counted == null) {
            counted = new Answer();
            perCluster.put(clusterId, counted);
        }
        counted.tell(whenTheAnswerArrives);
        if (counted.shouldAsk()) {
            final Answer asked = counted;
            asked.asking();
            AsyncDataProvider.getInstance().getHostListByClusterId(
                    new AsyncQuery<>(hosts -> asked.arrived(hosts == null ? UNCOUNTABLE : hosts.size())),
                    clusterId);
        }
        return counted.value(UNCOUNTABLE);
    }

    /**
     * A number that has been asked for, and the number once it comes back.
     *
     * <p>A number that came back is kept and handed out even while it is being asked for again,
     * so a refresh never takes an answer away. One that has never come back is worth waiting for
     * only so long; after that the caller is told to carry on without it.</p>
     *
     * <p>Everyone who asked while it was unknown is told when it arrives, not only whoever asked
     * first. Two buttons can be waiting on one cluster - the one on the toolbar and the one in the
     * menu beside it - and a question is asked once for both of them.</p>
     */
    static class Answer {

        private final long firstAskedAt = clock.getAsLong();

        private final Set<Runnable> waiting = new LinkedHashSet<>();

        private long lastAskedAt;

        private Integer known;

        boolean shouldAsk() {
            return lastAskedAt == 0 || waited(lastAskedAt);
        }

        void asking() {
            lastAskedAt = clock.getAsLong();
        }

        /** Remembers someone to tell, unless there is already an answer to give them. */
        void tell(Runnable whenTheAnswerArrives) {
            if (known == null) {
                waiting.add(whenTheAnswerArrives);
            }
        }

        void arrived(int answer) {
            known = Integer.valueOf(answer);
            List<Runnable> toTell = new ArrayList<>(waiting);
            waiting.clear();
            for (Runnable waiter : toTell) {
                waiter.run();
            }
        }

        /**
         * @param ifNobodyAnswers what to say once an unanswered question has waited long enough
         * @return the number, or {@code null} while the question is still worth waiting for
         */
        Integer value(int ifNobodyAnswers) {
            if (known != null) {
                return known;
            }
            return waited(firstAskedAt) ? Integer.valueOf(ifNobodyAnswers) : null;
        }

        private boolean waited(long since) {
            return clock.getAsLong() - since > FORGET_AFTER_MILLIS;
        }
    }
}
