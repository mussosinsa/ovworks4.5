package org.ovirt.engine.ui.webadmin.section.main.view.popup;

import org.ovirt.engine.ui.uicommonweb.ErrorPopupManager;
import org.ovirt.engine.ui.uicommonweb.TypeResolver;

/**
 * Tells the administrator that a setting they have just changed is not in force yet.
 *
 * <p>Several of these screens write a value that the engine, or httpd, reads when it starts. The
 * screen says the change was saved, which is true and is read as "done" - so the administrator
 * leaves, and the setting sits saved and not applied until something restarts for another reason.
 * Saying it in a window that has to be dismissed is what makes the difference between a setting
 * that was changed and one that is in force.</p>
 */
public final class RestartRequiredNotice {

    /** Two lines: what has to happen, and why it has to happen. */
    static final String MESSAGE =
            "환경변수 수정 후에는 적용을 위해서 다시 시작해야 합니다.\n" //$NON-NLS-1$
                    + "수정된 설정값을 시스템에 완전히 적용하려면 서버 또는 서비스를 다시 시작해야 합니다."; //$NON-NLS-1$

    private RestartRequiredNotice() {
    }

    /**
     * The window's title. The notice follows a change that was made, so it is not shown under
     * the error caption ("작업이 취소되었습니다"), which would say the opposite.
     */
    static final String CAPTION = "알림"; //$NON-NLS-1$

    /** Shows the notice on its own, for a screen that reports its result on the page. */
    public static void show() {
        showMessage(MESSAGE, CAPTION);
    }

    /**
     * Shows the notice under what the screen was going to say anyway.
     *
     * <p>A screen that already confirms in a window of its own gets one window rather than two:
     * a second dialog to dismiss straight after the first is read as something having gone wrong.</p>
     *
     * @param confirmation what the screen reports, shown first
     */
    public static void showWith(String confirmation) {
        showWith(confirmation, CAPTION);
    }

    /**
     * As {@link #showWith(String)}, under a title that says what was done.
     *
     * @param caption the window's title, such as "삭제되었습니다"
     */
    public static void showWith(String confirmation, String caption) {
        showMessage(withNotice(confirmation), caption == null || caption.isEmpty() ? CAPTION : caption);
    }

    /** @return the confirmation and the notice, as one message */
    static String withNotice(String confirmation) {
        if (confirmation == null || confirmation.trim().isEmpty()) {
            return MESSAGE;
        }
        return confirmation.trim() + "\n\n" + MESSAGE; //$NON-NLS-1$
    }

    private static void showMessage(String message, String caption) {
        ErrorPopupManager popupManager =
                (ErrorPopupManager) TypeResolver.getInstance().resolve(ErrorPopupManager.class);
        if (popupManager != null) {
            popupManager.show(message, caption);
        }
    }
}
