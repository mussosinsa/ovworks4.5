package org.ovirt.engine.ui.common.widget.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.ovirt.engine.ui.common.widget.action.ClusterHostCount.Answer;

public class ClusterHostCountTest {

    private long now;

    @BeforeEach
    public void holdTheClock() {
        now = 1_000_000L;
        ClusterHostCount.clock = () -> now;
    }

    @AfterEach
    public void letItRunAgain() {
        ClusterHostCount.clock = System::currentTimeMillis;
    }

    @Test
    public void aQuestionNotYetAskedIsAsked() {
        assertTrue(new Answer().shouldAsk());
    }

    @Test
    public void andIsNotAskedAgainWhileItIsStillOutstanding() {
        Answer answer = new Answer();
        answer.asking();

        now += ClusterHostCount.FORGET_AFTER_MILLIS;
        assertFalse(answer.shouldAsk());

        now += 1;
        assertTrue(answer.shouldAsk());
    }

    @Test
    public void whileNobodyHasAnsweredThereIsNoAnswer() {
        Answer answer = new Answer();
        answer.asking();

        assertNull(answer.value(ClusterHostCount.UNCOUNTABLE));
    }

    /**
     * A query that fails calls nobody back. Waiting forever for it would leave a button grey for
     * as long as the tab stayed open, so after long enough the caller is told to carry on.
     */
    @Test
    public void butNotForever() {
        Answer answer = new Answer();
        answer.asking();

        now += ClusterHostCount.FORGET_AFTER_MILLIS + 1;

        assertEquals(Integer.valueOf(ClusterHostCount.UNCOUNTABLE),
                answer.value(ClusterHostCount.UNCOUNTABLE));
    }

    @Test
    public void anAnswerThatArrivedIsTheAnswer() {
        Answer answer = new Answer();
        answer.asking();
        answer.arrived(4);

        assertEquals(Integer.valueOf(4), answer.value(ClusterHostCount.UNCOUNTABLE));
    }

    /** Asking again is a refresh, and a refresh never takes the last answer away. */
    @Test
    public void andIsStillTheAnswerWhileItIsBeingAskedAgain() {
        Answer answer = new Answer();
        answer.asking();
        answer.arrived(4);

        now += ClusterHostCount.FORGET_AFTER_MILLIS + 1;

        assertTrue(answer.shouldAsk());
        assertEquals(Integer.valueOf(4), answer.value(ClusterHostCount.UNCOUNTABLE));
    }
}
