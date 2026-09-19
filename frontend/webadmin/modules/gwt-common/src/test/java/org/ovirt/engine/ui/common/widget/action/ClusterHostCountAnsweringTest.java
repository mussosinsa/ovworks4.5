package org.ovirt.engine.ui.common.widget.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.common.businessentities.VDS;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.ui.frontend.AsyncQuery;
import org.ovirt.engine.ui.uicommonweb.dataprovider.AsyncDataProvider;

/**
 * What the count says while it is being asked for, once it arrives, and if it never does.
 */
public class ClusterHostCountAnsweringTest {

    /** An administration application that answers what this test tells it to. */
    private static class Answering extends AsyncDataProvider {

        private Object minimum;

        private int timesAsked;

        private AsyncQuery<List<VDS>> outstanding;

        @Override
        public Object getConfigValuePreConverted(ConfigValues configValue) {
            return configValue == ConfigValues.MinimumHostsForMigration ? minimum : null;
        }

        @Override
        public void getHostListByClusterId(AsyncQuery<List<VDS>> aQuery, Guid clusterId) {
            timesAsked++;
            outstanding = aQuery;
        }

        void answerWith(int hosts) {
            List<VDS> found = new ArrayList<>();
            for (int i = 0; i < hosts; i++) {
                found.add(new VDS());
            }
            outstanding.getAsyncCallback().onSuccess(found);
        }
    }

    private static final Guid A_CLUSTER = Guid.newGuid();

    private Answering engine;

    private long now;

    private int toldTheAnswerArrived;

    @BeforeEach
    public void setUp() {
        now = 1_000_000L;
        ClusterHostCount.clock = () -> now;
        ClusterHostCount.forget();
        engine = new Answering();
        AsyncDataProvider.setInstance(engine);
        toldTheAnswerArrived = 0;
    }

    @AfterEach
    public void tearDown() {
        ClusterHostCount.clock = System::currentTimeMillis;
        ClusterHostCount.forget();
        AsyncDataProvider.setInstance(null);
    }

    private Boolean ask() {
        return ClusterHostCount.enoughToMigrateWithin(A_CLUSTER, () -> toldTheAnswerArrived++);
    }

    /** One host is no restriction at all, so nothing needs counting. */
    @Test
    public void aMinimumOfOneAsksNobodyAnything() {
        engine.minimum = Integer.valueOf(1);

        assertEquals(Boolean.TRUE, ask());
        assertEquals(0, engine.timesAsked);
    }

    /** An option that was never read leaves the rule to the engine. */
    @Test
    public void andSoDoesAMinimumThatIsNotThere() {
        engine.minimum = null;

        assertEquals(Boolean.TRUE, ask());
        assertEquals(0, engine.timesAsked);
    }

    @Test
    public void aClusterNotYetCountedIsAskedAboutOnceAndHasNoAnswerMeanwhile() {
        engine.minimum = Integer.valueOf(3);

        assertNull(ask());
        assertNull(ask());
        assertEquals(1, engine.timesAsked);
    }

    @Test
    public void aClusterTooSmallToMigrateWithin() {
        engine.minimum = Integer.valueOf(3);
        ask();

        engine.answerWith(2);

        assertEquals(Boolean.FALSE, ask());
        assertEquals(1, toldTheAnswerArrived);
    }

    @Test
    public void andOneBigEnough() {
        engine.minimum = Integer.valueOf(3);
        ask();

        engine.answerWith(3);

        assertEquals(Boolean.TRUE, ask());
    }

    /** The answer is not asked for again on every redraw, only once it has gone stale. */
    @Test
    public void anAnswerIsKeptForAWhileAndThenAskedAgain() {
        engine.minimum = Integer.valueOf(3);
        ask();
        engine.answerWith(4);

        now += ClusterHostCount.FORGET_AFTER_MILLIS;
        assertEquals(Boolean.TRUE, ask());
        assertEquals(1, engine.timesAsked);

        now += 1;
        assertEquals(Boolean.TRUE, ask(), "the answer it has stands while the next one is asked for"); //$NON-NLS-1$
        assertEquals(2, engine.timesAsked);
    }

    /**
     * A query that fails calls nobody back. The button must not stay grey for as long as the tab
     * is open because of it, so after long enough the engine is left to judge the migration.
     */
    @Test
    public void aQuestionNobodyAnswersIsNotWaitedForForever() {
        engine.minimum = Integer.valueOf(3);
        assertNull(ask());

        now += ClusterHostCount.FORGET_AFTER_MILLIS + 1;

        assertEquals(Boolean.TRUE, ask());
    }

    @Test
    public void aMachineInNoClusterIsNotCounted() {
        engine.minimum = Integer.valueOf(3);

        assertEquals(Boolean.TRUE, ClusterHostCount.enoughToMigrateWithin(null, () -> { }));
        assertEquals(0, engine.timesAsked);
    }

    /** Nothing came back at all, which is not the same as nothing being there. */
    @Test
    public void anEmptyAnswerIsLeftToTheEngine() {
        engine.minimum = Integer.valueOf(3);
        ask();

        engine.outstanding.getAsyncCallback().onSuccess(null);

        assertEquals(Boolean.TRUE, ask());
    }

    @Test
    public void nothingIsRememberedOnceItIsLetGoOf() {
        engine.minimum = Integer.valueOf(3);
        ask();
        engine.answerWith(2);
        assertEquals(Boolean.FALSE, ask());

        ClusterHostCount.forget();

        assertNull(ask());
        assertTrue(engine.timesAsked > 1);
        assertFalse(Boolean.FALSE.equals(ask()));
    }
}
