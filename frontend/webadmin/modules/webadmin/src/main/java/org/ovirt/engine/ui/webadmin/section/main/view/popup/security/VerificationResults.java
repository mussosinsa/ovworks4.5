package org.ovirt.engine.ui.webadmin.section.main.view.popup.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;

import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.businessentities.AuditLog;

/**
 * The results of the latest self-test and integrity verification, item by item, read back from
 * the audit log.
 *
 * <p>The engine records every item of a run after the record saying the run started, whoever
 * asked for it - the engine start, the timer or this screen:</p>
 * <ul>
 * <li>{@code 자체시험 <결과> : [프로세스: <process> | 항목: <item>] <what was found>} (earlier
 * records without the colon are read as well)</li>
 * <li>{@code 무결성 검증 <결과> [프로세스: <process> | <변경|삭제|추가|파일 N개>] <what was found>}</li>
 * </ul>
 * <p>The latest run's items are the ones recorded since the latest such start, in the order they
 * were recorded.</p>
 *
 * <p>Plain Java, no widgets: the screen renders what this returns.</p>
 */
final class VerificationResults {

    static final String SELF_TEST = "자체시험 "; //$NON-NLS-1$
    static final String INTEGRITY = "무결성 검증 "; //$NON-NLS-1$
    private static final String PROCESS = " [프로세스: "; //$NON-NLS-1$
    private static final String ITEM = " | "; //$NON-NLS-1$
    private static final String ITEM_LABEL = "항목: "; //$NON-NLS-1$
    private static final String END = "] "; //$NON-NLS-1$
    /** What the self-test's records put between the result and the item: {@code 자체시험 실패 : [...]}. */
    private static final String COLON = " :"; //$NON-NLS-1$

    /** One item of one process. */
    static final class Row {
        private final String process;
        private final String item;
        private final String result;
        private final String text;
        private final Date time;

        Row(String process, String item, String result, String text, Date time) {
            this.process = process;
            this.item = item;
            this.result = result;
            this.text = text;
            this.time = time;
        }

        String getProcess() {
            return process;
        }

        String getItem() {
            return item;
        }

        /** 성공, 실패, 경고 or 제외. */
        String getResult() {
            return result;
        }

        String getText() {
            return text;
        }

        Date getTime() {
            return time;
        }
    }

    private VerificationResults() {
    }

    /** @return the items of the latest self-test run, or none when no run is in the audit log */
    static List<Row> latestSelfTest(List<AuditLog> logs) {
        return latest(logs, AuditLogType.SECURITY_AUDIT_STARTED, SELF_TEST);
    }

    /** @return the records of the latest integrity verification, or none */
    static List<Row> latestIntegrity(List<AuditLog> logs) {
        return latest(logs, AuditLogType.INTEGRITY_VERIFICATION_STARTED, INTEGRITY);
    }

    private static List<Row> latest(List<AuditLog> logs, AuditLogType startType, final String prefix) {
        AuditLog started = null;
        for (AuditLog log : logs) {
            if (log.getLogType() == startType
                    && (started == null || log.getAuditLogId() > started.getAuditLogId())) {
                started = log;
            }
        }
        List<Row> rows = new ArrayList<>();
        if (started == null) {
            return rows;
        }
        List<AuditLog> items = new ArrayList<>();
        for (AuditLog log : logs) {
            if (log.getAuditLogId() > started.getAuditLogId() && parse(log, prefix) != null) {
                items.add(log);
            }
        }
        Collections.sort(items, new Comparator<AuditLog>() {
            @Override
            public int compare(AuditLog first, AuditLog second) {
                return Long.compare(first.getAuditLogId(), second.getAuditLogId());
            }
        });
        for (AuditLog log : items) {
            rows.add(parse(log, prefix));
        }
        return rows;
    }

    /** @return the row the record is, or null when it is not one item of the given check */
    static Row parse(AuditLog log, String prefix) {
        String message = log.getMessage();
        if (message == null || !message.startsWith(prefix)) {
            return null;
        }
        int process = message.indexOf(PROCESS);
        if (process < 0) {
            return null;
        }
        String result = message.substring(prefix.length(), process);
        if (result.endsWith(COLON)) {
            result = result.substring(0, result.length() - COLON.length());
        }
        if (result.indexOf(' ') >= 0) {
            // "자체시험 실패 상세 (...)" - the detail record, not an item.
            return null;
        }
        int item = message.indexOf(ITEM, process);
        int end = item < 0 ? -1 : message.indexOf(END, item);
        if (end < 0) {
            return null;
        }
        String itemText = message.substring(item + ITEM.length(), end);
        if (itemText.startsWith(ITEM_LABEL)) {
            itemText = itemText.substring(ITEM_LABEL.length());
        }
        return new Row(
                message.substring(process + PROCESS.length(), item),
                itemText,
                result,
                message.substring(end + END.length()),
                log.getLogTime());
    }
}
