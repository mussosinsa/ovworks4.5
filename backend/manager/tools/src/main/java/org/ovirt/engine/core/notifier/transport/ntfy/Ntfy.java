package org.ovirt.engine.core.notifier.transport.ntfy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.common.AuditLogSeverity;
import org.ovirt.engine.core.common.EventNotificationMethod;
import org.ovirt.engine.core.notifier.dao.DispatchResult;
import org.ovirt.engine.core.notifier.filter.AuditLogEvent;
import org.ovirt.engine.core.notifier.transport.Transport;
import org.ovirt.engine.core.notifier.utils.NotificationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Pushes event notifications to an ntfy server (binwiederhier/ntfy).
 *
 * <p>One HTTP POST per event to {@code NTFY_URL/<topic>}, the message as the body, with the
 * {@code Title}, {@code Priority} and {@code Tags} headers and, when a publisher token is configured,
 * {@code Authorization: Bearer <token>} - the same request as
 * {@code curl -H "Authorization: Bearer $TOKEN" -H "Title: ..." -H "Priority: high" --data-binary '...' URL/topic}.</p>
 *
 * <p>The address a filter names ({@code ntfy:<topic>}) selects the topic; an empty one is
 * {@code NTFY_TOPIC}. Sending happens on the idle task, with retries, so that a slow or unreachable
 * server never holds up reading the events.</p>
 */
public class Ntfy extends Transport {

    private static final Logger log = LoggerFactory.getLogger(Ntfy.class);

    public static final String NAME = "ntfy";

    static final String NTFY_URL = "NTFY_URL";
    static final String NTFY_TOPIC = "NTFY_TOPIC";
    static final String NTFY_TOKEN = "NTFY_TOKEN";
    static final String NTFY_TOKEN_FILE = "NTFY_TOKEN_FILE";
    static final String NTFY_CA_FILE = "NTFY_CA_FILE";
    static final String NTFY_ALLOW_INSECURE_HTTP = "NTFY_ALLOW_INSECURE_HTTP";
    static final String NTFY_TIMEOUT_SECONDS = "NTFY_TIMEOUT_SECONDS";
    static final String NTFY_RETRIES = "NTFY_RETRIES";
    static final String NTFY_SEND_INTERVAL = "NTFY_SEND_INTERVAL";
    static final String NTFY_PRIORITY_PREFIX = "NTFY_PRIORITY_";
    static final String NTFY_TAGS = "NTFY_TAGS";

    private static final Set<String> PRIORITIES = new HashSet<>(Arrays.asList(
            "1", "2", "3", "4", "5", "min", "low", "default", "high", "urgent", "max"));

    /** Topic names ntfy accepts. */
    private static final String TOPIC_PATTERN = "[-_A-Za-z0-9]{1,64}";

    private static final int MAX_ERROR_BODY = 512;

    private final String baseUrl;
    private final String defaultTopic;
    private final String token;
    private final SSLSocketFactory sslSocketFactory;
    private final int timeoutMillis;
    private final int retries;
    private final int sendIntervals;
    private final String extraTags;
    private final String hostName;
    private final NotificationProperties props;
    private int lastSendInterval = 0;
    private final Queue<Attempt> sendQueue = new LinkedBlockingQueue<>();

    /**
     * @param props the notifier configuration
     * @throws IllegalArgumentException when ntfy is selected but its settings are incomplete or invalid
     */
    public Ntfy(NotificationProperties props) {
        this.props = props;
        String url = StringUtils.trimToEmpty(props.getProperty(NTFY_URL, true));
        if (url.isEmpty()) {
            throw new IllegalArgumentException("NTFY_URL must be set when ntfy is selected in NOTIFICATION_CHANNELS");
        }
        baseUrl = StringUtils.stripEnd(url, "/");
        String lower = baseUrl.toLowerCase(Locale.ROOT);
        if (!lower.startsWith("https://") && !lower.startsWith("http://")) {
            throw new IllegalArgumentException("NTFY_URL must be an http(s) URL: " + baseUrl);
        }
        defaultTopic = StringUtils.trimToEmpty(props.getProperty(NTFY_TOPIC, true));
        if (!defaultTopic.isEmpty() && !defaultTopic.matches(TOPIC_PATTERN)) {
            throw new IllegalArgumentException("NTFY_TOPIC is not a valid ntfy topic: " + defaultTopic);
        }
        token = readToken(props);
        if (lower.startsWith("http://") && !props.getBoolean(NTFY_ALLOW_INSECURE_HTTP, false)) {
            // The publisher token and the event text would cross the network in the clear.
            throw new IllegalArgumentException(
                    "NTFY_URL uses http://; use https:// or set NTFY_ALLOW_INSECURE_HTTP=true");
        }
        if (token == null) {
            log.warn("ntfy: no publisher token configured (NTFY_TOKEN / NTFY_TOKEN_FILE); publishing anonymously");
        }
        sslSocketFactory = sslSocketFactory(StringUtils.trimToEmpty(props.getProperty(NTFY_CA_FILE, true)));
        timeoutMillis = positive(props, NTFY_TIMEOUT_SECONDS, 10) * 1000;
        retries = Math.max(1, nonNegative(props, NTFY_RETRIES, 3));
        sendIntervals = nonNegative(props, NTFY_SEND_INTERVAL, 0);
        extraTags = StringUtils.trimToEmpty(props.getProperty(NTFY_TAGS, true));
        for (AuditLogSeverity severity : AuditLogSeverity.values()) {
            priority(severity);
        }
        String host;
        try {
            host = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            host = "localhost";
        }
        hostName = host;
        log.info("ntfy transport enabled: url='{}', default topic='{}', token={}",
                baseUrl, defaultTopic, token == null ? "none" : "configured");
    }

    private static String readToken(NotificationProperties props) {
        String file = StringUtils.trimToEmpty(props.getProperty(NTFY_TOKEN_FILE, true));
        if (!file.isEmpty()) {
            try {
                String value = new String(Files.readAllBytes(Paths.get(file)), StandardCharsets.UTF_8).trim();
                if (value.isEmpty()) {
                    throw new IllegalArgumentException("NTFY_TOKEN_FILE is empty: " + file);
                }
                return value;
            } catch (IOException e) {
                throw new IllegalArgumentException("Cannot read NTFY_TOKEN_FILE " + file + ": " + e.getMessage());
            }
        }
        String value = StringUtils.trimToEmpty(props.getProperty(NTFY_TOKEN, true));
        return value.isEmpty() ? null : value;
    }

    private static SSLSocketFactory sslSocketFactory(String caFile) {
        if (caFile.isEmpty()) {
            return null;
        }
        try (InputStream in = Files.newInputStream(Paths.get(caFile))) {
            Collection<? extends Certificate> certificates =
                    CertificateFactory.getInstance("X.509").generateCertificates(in);
            if (certificates.isEmpty()) {
                throw new IllegalArgumentException("NTFY_CA_FILE holds no certificate: " + caFile);
            }
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
            trust.load(null, null);
            int i = 0;
            for (Certificate certificate : certificates) {
                trust.setCertificateEntry("ntfy-ca-" + i++, certificate);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tmf.getTrustManagers(), null);
            return context.getSocketFactory();
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalArgumentException("Cannot load NTFY_CA_FILE " + caFile + ": " + e.getMessage());
        }
    }

    private static int nonNegative(NotificationProperties props, String key, int fallback) {
        String value = StringUtils.trimToEmpty(props.getProperty(key, true));
        if (value.isEmpty()) {
            return fallback;
        }
        return props.validateNonNegetive(key);
    }

    private static int positive(NotificationProperties props, String key, int fallback) {
        int value = nonNegative(props, key, fallback);
        if (value <= 0) {
            throw new IllegalArgumentException(key + " must be greater than 0");
        }
        return value;
    }

    /** @return the ntfy priority for an event severity, from NTFY_PRIORITY_{severity} or the default */
    String priority(AuditLogSeverity severity) {
        String configured = severity == null
                ? null
                : StringUtils.trimToEmpty(props.getProperty(NTFY_PRIORITY_PREFIX + severity.name(), true));
        if (StringUtils.isEmpty(configured)) {
            return defaultPriority(severity);
        }
        String value = configured.toLowerCase(Locale.ROOT);
        if (!PRIORITIES.contains(value)) {
            throw new IllegalArgumentException(NTFY_PRIORITY_PREFIX + severity.name()
                    + " must be one of " + PRIORITIES + ": " + configured);
        }
        return value;
    }

    static String defaultPriority(AuditLogSeverity severity) {
        if (severity == null) {
            return "default";
        }
        switch (severity) {
        case ALERT:
            return "urgent";
        case ERROR:
            return "high";
        case WARNING:
            return "default";
        default:
            return "low";
        }
    }

    static String defaultTag(AuditLogSeverity severity) {
        if (severity == null) {
            return "information_source";
        }
        switch (severity) {
        case ALERT:
            return "rotating_light";
        case ERROR:
            return "x";
        case WARNING:
            return "warning";
        default:
            return "information_source";
        }
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public boolean isActive() {
        return true;
    }

    @Override
    public void dispatchEvent(AuditLogEvent event, String address) {
        String topic = StringUtils.isBlank(address) ? defaultTopic : address.trim();
        if (topic.isEmpty()) {
            log.error("ntfy: no topic for event {} (set NTFY_TOPIC or use ntfy:<topic>)", event.getName());
            notifyObservers(DispatchResult.failure(event, address, EventNotificationMethod.NTFY, "no ntfy topic"));
            return;
        }
        if (!topic.matches(TOPIC_PATTERN)) {
            log.error("ntfy: invalid topic '{}' for event {}", topic, event.getName());
            notifyObservers(DispatchResult.failure(event, address, EventNotificationMethod.NTFY,
                    "invalid ntfy topic"));
            return;
        }
        sendQueue.add(new Attempt(event, topic));
    }

    @Override
    public void idle() {
        if (lastSendInterval++ < sendIntervals) {
            return;
        }
        lastSendInterval = 0;
        Iterator<Attempt> iterator = sendQueue.iterator();
        while (iterator.hasNext()) {
            Attempt attempt = iterator.next();
            try {
                publish(attempt);
                log.info("ntfy: event {} (id {}) pushed to topic '{}'",
                        attempt.event.getName(), attempt.event.getId(), attempt.topic);
                notifyObservers(DispatchResult.success(attempt.event, attempt.topic, EventNotificationMethod.NTFY));
                iterator.remove();
            } catch (Exception e) {
                attempt.tries++;
                log.warn("ntfy: push of event {} to topic '{}' failed ({}/{}): {}",
                        attempt.event.getName(), attempt.topic, attempt.tries, retries, e.getMessage());
                if (attempt.tries >= retries) {
                    notifyObservers(DispatchResult.failure(attempt.event, attempt.topic,
                            EventNotificationMethod.NTFY, StringUtils.left(e.getMessage(), 200)));
                    iterator.remove();
                }
            }
        }
    }

    String title(AuditLogEvent event) {
        return "[" + hostName + "] " + (event.getSeverity() == null ? "" : event.getSeverity().name() + " ")
                + event.getName();
    }

    String body(AuditLogEvent event) {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", Locale.ROOT);
        StringBuilder body = new StringBuilder();
        body.append(StringUtils.defaultString(event.getMessage()));
        body.append("\n\n").append(format.format(event.getLogTime()));
        body.append(" | ").append(event.getName());
        body.append(" | ").append(hostName);
        return body.toString();
    }

    String tags(AuditLogEvent event) {
        String tag = defaultTag(event.getSeverity());
        return extraTags.isEmpty() ? tag : tag + "," + extraTags;
    }

    private void publish(Attempt attempt) throws IOException {
        URL url = new URL(baseUrl + "/" + URLEncoder.encode(attempt.topic, StandardCharsets.UTF_8.name()));
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        try {
            if (sslSocketFactory != null && connection instanceof HttpsURLConnection) {
                ((HttpsURLConnection) connection).setSSLSocketFactory(sslSocketFactory);
            }
            connection.setConnectTimeout(timeoutMillis);
            connection.setReadTimeout(timeoutMillis);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "text/plain; charset=utf-8");
            connection.setRequestProperty("Title", headerValue(title(attempt.event)));
            connection.setRequestProperty("Priority", priority(attempt.event.getSeverity()));
            connection.setRequestProperty("Tags", headerValue(tags(attempt.event)));
            if (token != null) {
                connection.setRequestProperty("Authorization", "Bearer " + token);
            }
            byte[] payload = body(attempt.event).getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(payload.length);
            try (OutputStream out = connection.getOutputStream()) {
                out.write(payload);
            }
            int status = connection.getResponseCode();
            if (status < 200 || status >= 300) {
                throw new IOException("HTTP " + status + ": " + errorBody(connection));
            }
            drain(connection.getInputStream());
        } finally {
            connection.disconnect();
        }
    }

    /**
     * Header values travel as ISO-8859-1; ntfy decodes RFC 2047 encoded words, so a value that is not
     * plain ASCII (a Korean host or tag, say) is sent as one.
     */
    static String headerValue(String value) {
        String clean = value.replaceAll("[\\r\\n]+", " ");
        if (StandardCharsets.US_ASCII.newEncoder().canEncode(clean)) {
            return clean;
        }
        return "=?UTF-8?B?" + Base64.getEncoder().encodeToString(clean.getBytes(StandardCharsets.UTF_8)) + "?=";
    }

    private static String errorBody(HttpURLConnection connection) {
        try (InputStream in = connection.getErrorStream()) {
            if (in == null) {
                return StringUtils.defaultString(connection.getResponseMessage());
            }
            return StringUtils.left(new String(readAll(in), StandardCharsets.UTF_8).trim(), MAX_ERROR_BODY);
        } catch (IOException e) {
            return e.getMessage();
        }
    }

    private static void drain(InputStream in) throws IOException {
        try (InputStream stream = in) {
            readAll(stream);
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    int queued() {
        return sendQueue.size();
    }

    private static final class Attempt {
        private final AuditLogEvent event;
        private final String topic;
        private int tries;

        private Attempt(AuditLogEvent event, String topic) {
            this.event = event;
            this.topic = topic;
        }
    }
}
