// Modified by 새올정보기술 for OV-Works (2026). Changes against oVirt Engine 4.5.6: docs/ovworks-source-change-statement.md
package org.ovirt.engine.ui.uicommonweb;

public interface ErrorPopupManager {

    void show(String errorMessage);

    /**
     * Shows a message under a title of its own rather than the error caption - for a window that
     * reports something done, which the error caption ("작업이 취소되었습니다") would misreport.
     *
     * @param caption the window's title, or null for the error caption
     */
    default void show(String message, String caption) {
        show(message);
    }

}
