package org.ovirt.engine.core.notifier.filter;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.common.AuditLogSeverity;
import org.ovirt.engine.core.common.utils.ToStringBuilder;
import org.ovirt.engine.core.notifier.transport.Transport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FirstMatchSimpleFilter {

    private static final Pattern PATTERN_BLANK = Pattern.compile("\\s*");
    private static final Pattern PATTERN_PARSE = Pattern.compile(
            "\\s*" +
            "((?<include>include)|(?<exclude>exclude))" +
            ":" +
            "((?<anymsg>\\*)|(?<message>\\w+))" +
            "(" +
                ":" +
                "(?<severity>\\*|ALERT|ERROR|WARNING|NORMAL)" +
            ")?" +
            "(?<recipient>" +
                "\\(" +
                    "(" +
                        "(?<anyrecipient>\\*)|" +
                        "(?<transport>\\w+):(?<name>[^)]*)" +
                    ")" +
                "\\)" +
            ")?" +
            "\\s*" +
            ""
        );
    private static final Logger log = LoggerFactory.getLogger(FirstMatchSimpleFilter.class);
    private Map<String, Transport> transports = new HashMap<>();
    private List<FilterEntry> notify = new LinkedList<>();
    private Set<Recipient> recipients = new HashSet<>();

    /** Transport whose subscriptions are also delivered through {@link #mirror}. */
    private String mirroredTransport;

    /** Delivers, once per event, what matched a subscription of {@link #mirroredTransport}. */
    private Transport mirror;

    public void registerTransport(Transport transport) {
        transports.put(transport.getName(), transport);
    }

    /**
     * Makes each event that matches a subscription of one transport also go, once, to another -
     * to its default address. This is how the e-mail subscriptions of the administration portal
     * decide what is pushed through ntfy, without a subscription of its own for every event.
     *
     * @param from the transport whose subscriptions are followed, e.g. {@code smtp}
     * @param to the transport that delivers them; null stops mirroring
     */
    public void setSubscriptionMirror(String from, Transport to) {
        mirroredTransport = from;
        mirror = to;
    }

    public void unregisterTransport(Transport transport) {
        transports.remove(transport.getName());
    }

    private void addRecipient(Recipient recipient) {
        recipients.add(recipient);
    }

    public void addFilterEntries(List<FilterEntry> entries) {
        for (FilterEntry entry : entries) {
            log.debug("addFilterEntry: {}", entry);
            notify.add(entry);
            if (entry.getRecipient() != null) {
                addRecipient(entry.getRecipient());
            }
        }
    }

    public void clearFilterEntries() {
        notify.clear();
        recipients.clear();
    }

    public void processEvent(AuditLogEvent event) {
        log.debug("Event: {}", event.getName());
        boolean mirrored = false;
        boolean sentToMirrorDefault = false;
        for (Recipient recipient : recipients) {
            log.debug("Recipient: {}", recipient);
            for (FilterEntry entry : notify) {
                if ((
                        entry.getEventName() == null ||
                        entry.getEventName().equals(event.getName())
                        ) &&
                        (
                        entry.getSeverity() == null ||
                        (entry.isExclude() ? -1 : 1) * event.getSeverity().compareTo(entry.getSeverity()) >= 0
                        ) &&
                        (
                        entry.getRecipient() == null ||
                        entry.getRecipient().equals(recipient)
                        )) {
                    log.debug("Entry match(({})): {}", entry.isExclude() ? "exclude" : "include", entry);
                    if (!entry.isExclude()) {
                        if (mirror != null && recipient.getTransport().equals(mirroredTransport)) {
                            mirrored = true;
                        }
                        if (mirror != null && recipient.getTransport().equals(mirror.getName())
                                && StringUtils.isEmpty(recipient.getName())) {
                            sentToMirrorDefault = true;
                        }
                        Transport transport = transports.get(recipient.getTransport());
                        if (transport == null) {
                            log.debug("Ignoring recipient '{}' as transport not registered", recipient);
                        } else {
                            transport.dispatchEvent(event, recipient.getName());
                        }
                    }
                    break;
                }
            }
        }
        if (mirrored && !sentToMirrorDefault) {
            log.debug("Event {} matched a {} subscription; also sent through {}",
                    event.getName(), mirroredTransport, mirror.getName());
            mirror.dispatchEvent(event, "");
        }
    }

    public static List<FilterEntry> parse(String filters) {
        List<FilterEntry> ret = new LinkedList<>();
        if (!PATTERN_BLANK.matcher(filters).matches()) {
            Matcher m = PATTERN_PARSE.matcher(filters);
            boolean ok = false;
            int expectedStart = 0;
            while (m.find()) {
                log.debug("parse: handling '{}'", m.group(0));

                if (m.start() != expectedStart) {
                    throw new RuntimeException("Cannot parse filters");
                }
                expectedStart = m.end();
                ok = m.end() == m.regionEnd();

                ret.add(
                        new FilterEntry(
                                m.group("anymsg") != null ? null : m.group("message"),
                                m.group("severity") == null || m.group("severity").equals("*")
                                        ? null
                                        : AuditLogSeverity.valueOf(m.group("severity")),
                                m.group("exclude") != null,
                                m.group("recipient") == null || m.group("anyrecipient") != null ? null : new Recipient(
                                        m.group("transport"),
                                        m.group("name")
                                )
                        )
                        );
            }
            if (!ok) {
                throw new IllegalArgumentException("Cannot parse filters");
            }
        }
        return ret;
    }

    public static class Recipient {

        private final String transport;

        private final String name;

        public Recipient(String transport, String name) {
            this.transport = transport;
            this.name = name;
        }

        public String getTransport() {
            return transport;
        }

        public String getName() {
            return name;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Recipient)) {
                return false;
            }
            Recipient other = (Recipient) obj;
            return Objects.equals(transport, other.transport)
                    && Objects.equals(name, other.name);
        }

        @Override
        public int hashCode() {
            return Objects.hash(
                    transport,
                    name
            );
        }

        @Override
        public String toString() {
            return ToStringBuilder.forInstance(this)
                    .append("transport", transport)
                    .append("name", name)
                    .build();
        }
    }

    public static class FilterEntry {

        private final String eventName;

        private final AuditLogSeverity severity;

        private final boolean exclude;

        private final Recipient recipient;

        public FilterEntry(String eventName, AuditLogSeverity severity, boolean exclude, Recipient recipient) {
            this.eventName = eventName;
            this.severity = severity;
            this.exclude = exclude;
            this.recipient = recipient;
        }

        public FilterEntry(String eventName, AuditLogSeverity severity, boolean exclude, String transport, String name) {
            this(eventName, severity, exclude, new Recipient(transport, name));
        }

        public String getEventName() {
            return eventName;
        }

        public AuditLogSeverity getSeverity() {
            return severity;
        }

        public boolean isExclude() {
            return exclude;
        }

        public Recipient getRecipient() {
            return recipient;
        }

        @Override
        public String toString() {
            return ToStringBuilder.forInstance(this)
                    .append("eventName", eventName)
                    .append("severity", severity != null ? severity.name() : "any")
                    .append("exclude", exclude)
                    .append("recipient", recipient)
                    .build();
        }
    }
}
