package org.ovirt.engine.ui.webadmin.section.main.view.popup;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * A screen that already confirms in a window of its own gets one window, not two.
 */
class RestartRequiredNoticeTest {

    @Test
    void saysWhatWasDoneBeforeSayingWhatIsStillNeeded() {
        String confirmation = "단말기 인증이 적용되었습니다."; //$NON-NLS-1$

        String message = RestartRequiredNotice.withNotice(confirmation);

        assertTrue(message.startsWith(confirmation));
        assertTrue(message.endsWith(RestartRequiredNotice.MESSAGE));
    }

    @Test
    void saysOnlyTheNoticeWhenTheScreenHasNothingToConfirm() {
        assertEquals(RestartRequiredNotice.MESSAGE, RestartRequiredNotice.withNotice(null));
        assertEquals(RestartRequiredNotice.MESSAGE, RestartRequiredNotice.withNotice("")); //$NON-NLS-1$
        assertEquals(RestartRequiredNotice.MESSAGE, RestartRequiredNotice.withNotice("   ")); //$NON-NLS-1$
    }

    @Test
    void separatesTheTwoSoNeitherReadsAsPartOfTheOther() {
        assertTrue(RestartRequiredNotice.withNotice("적용되었습니다.").contains("\n\n")); //$NON-NLS-1$ //$NON-NLS-2$
    }
}
