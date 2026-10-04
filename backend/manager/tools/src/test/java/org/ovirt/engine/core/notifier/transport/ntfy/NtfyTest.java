package org.ovirt.engine.core.notifier.transport.ntfy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ovirt.engine.core.common.AuditLogSeverity;
import org.ovirt.engine.core.common.EventNotificationMethod;
import org.ovirt.engine.core.notifier.dao.DispatchResult;
import org.ovirt.engine.core.notifier.filter.AuditLogEvent;
import org.ovirt.engine.core.notifier.utils.NotificationProperties;

public class NtfyTest {

    @TempDir
    Path dir;

    private ServerSocket server;
    private Thread serverThread;
    private final List<Request> requests = new CopyOnWriteArrayList<>();
    private volatile int status = 200;
    private final List<DispatchResult> results = new ArrayList<>();

    private static final class Request {
        String path;
        String title;
        String priority;
        String tags;
        String authorization;
        String body;
    }

    /** A one-request-per-connection HTTP endpoint, enough to stand in for an ntfy server. */
    @BeforeEach
    public void startServer() throws IOException {
        server = new ServerSocket(0, 10, InetAddress.getLoopbackAddress());
        serverThread = new Thread(() -> {
            while (!server.isClosed()) {
                try (Socket socket = server.accept()) {
                    handle(socket);
                } catch (IOException e) {
                    // closed
                }
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
    }

    private void handle(Socket socket) throws IOException {
        BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));
        Request request = new Request();
        request.path = in.readLine().split(" ")[1];
        int length = 0;
        String line;
        while ((line = in.readLine()) != null && !line.isEmpty()) {
            int colon = line.indexOf(':');
            String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(colon + 1).trim();
            switch (name) {
            case "title":
                request.title = value;
                break;
            case "priority":
                request.priority = value;
                break;
            case "tags":
                request.tags = value;
                break;
            case "authorization":
                request.authorization = value;
                break;
            case "content-length":
                length = Integer.parseInt(value);
                break;
            default:
                break;
            }
        }
        char[] chars = new char[length];
        int read = 0;
        while (read < length) {
            int n = in.read(chars, read, length - read);
            if (n < 0) {
                break;
            }
            read += n;
        }
        request.body = new String(new String(chars, 0, read).getBytes(StandardCharsets.ISO_8859_1),
                StandardCharsets.UTF_8);
        requests.add(request);
        byte[] answer = (status == 200 ? "{\"id\":\"x\"}" : "{\"error\":\"forbidden\"}")
                .getBytes(StandardCharsets.UTF_8);
        OutputStream out = socket.getOutputStream();
        out.write(("HTTP/1.1 " + status + " X\r\nContent-Length: " + answer.length
                + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        out.write(answer);
        out.flush();
    }

    @AfterEach
    public void stopServer() throws IOException {
        server.close();
        NotificationProperties.release();
    }

    private String url() {
        return "http://127.0.0.1:" + server.getLocalPort();
    }

    private NotificationProperties props(String... lines) throws IOException {
        Path conf = dir.resolve("notifier.conf");
        Files.write(conf, String.join("\n", lines).concat("\n").getBytes(StandardCharsets.UTF_8));
        NotificationProperties.release();
        NotificationProperties.setDefaults(conf.toString(), "");
        return NotificationProperties.getInstance();
    }

    private Ntfy ntfy(String... extra) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add("NTFY_URL=" + url());
        lines.add("NTFY_TOPIC=ops-alerts");
        lines.add("NTFY_ALLOW_INSECURE_HTTP=true");
        lines.add("NTFY_TOKEN=tk_publisher");
        for (String line : extra) {
            lines.add(line);
        }
        Ntfy ntfy = new Ntfy(props(lines.toArray(new String[0])));
        ntfy.registerObserver((o, result) -> results.add(result));
        return ntfy;
    }

    private static AuditLogEvent event(String name, AuditLogSeverity severity, String message) {
        AuditLogEvent event = new AuditLogEvent();
        event.setId(42);
        event.setLogTypeName(name);
        event.setSeverity(severity);
        event.setMessage(message);
        event.setLogTime(new Date(0));
        return event;
    }

    @Test
    public void pushesLikeTheCurlCommand() throws IOException {
        Ntfy ntfy = ntfy();
        ntfy.dispatchEvent(event("SECURITY_VERIFICATION_SCHEDULED_FAILED", AuditLogSeverity.ALERT,
                "app01 서버 장애가 감지되었습니다."), "");
        ntfy.idle();

        assertEquals(1, requests.size());
        Request request = requests.get(0);
        assertEquals("/ops-alerts", request.path);
        assertEquals("Bearer tk_publisher", request.authorization);
        assertEquals("urgent", request.priority);
        assertTrue(request.title.endsWith("ALERT SECURITY_VERIFICATION_SCHEDULED_FAILED"), request.title);
        assertTrue(request.tags.startsWith("rotating_light"), request.tags);
        assertTrue(request.body.startsWith("app01 서버 장애가 감지되었습니다."), request.body);
        assertEquals(1, results.size());
        assertTrue(results.get(0).isSuccess());
        assertEquals(EventNotificationMethod.NTFY, results.get(0).getNotificationMethod());
        assertEquals(0, ntfy.queued());
    }

    @Test
    public void anAddressPicksTheTopicAndSeverityPicksThePriority() throws IOException {
        Ntfy ntfy = ntfy("NTFY_PRIORITY_WARNING=high", "NTFY_TAGS=ovirt");
        ntfy.dispatchEvent(event("AUDIT_STORAGE_USAGE_WARNING", AuditLogSeverity.WARNING, "80%"), "storage");
        ntfy.idle();
        assertEquals("/storage", requests.get(0).path);
        assertEquals("high", requests.get(0).priority);
        assertEquals("warning,ovirt", requests.get(0).tags);
    }

    @Test
    public void retriesThenRecordsTheFailure() throws IOException {
        status = 403;
        Ntfy ntfy = ntfy("NTFY_RETRIES=2");
        ntfy.dispatchEvent(event("VDC_STOP", AuditLogSeverity.NORMAL, "stopped"), "");
        ntfy.idle();
        assertTrue(results.isEmpty());
        assertEquals(1, ntfy.queued());
        ntfy.idle();
        assertEquals(1, results.size());
        assertFalse(results.get(0).isSuccess());
        assertTrue(results.get(0).getErrorMessage().contains("HTTP 403"), results.get(0).getErrorMessage());
        assertEquals(0, ntfy.queued());
    }

    @Test
    public void theTokenCanComeFromAFile() throws IOException {
        Path token = Files.write(dir.resolve("token"), "tk_from_file\n".getBytes(StandardCharsets.UTF_8));
        Ntfy ntfy = new Ntfy(props("NTFY_URL=" + url(), "NTFY_TOPIC=ops-alerts",
                "NTFY_ALLOW_INSECURE_HTTP=true", "NTFY_TOKEN_FILE=" + token));
        ntfy.dispatchEvent(event("VDC_STOP", AuditLogSeverity.NORMAL, "stopped"), "");
        ntfy.idle();
        assertEquals("Bearer tk_from_file", requests.get(0).authorization);
    }

    @Test
    public void refusesPlainHttpUnlessAllowed() throws IOException {
        NotificationProperties props = props("NTFY_URL=" + url(), "NTFY_TOPIC=ops-alerts", "NTFY_TOKEN=t");
        assertThrows(IllegalArgumentException.class, () -> new Ntfy(props));
    }

    @Test
    public void rejectsIncompleteOrInvalidSettings() throws IOException {
        NotificationProperties noUrl = props("NTFY_TOPIC=ops-alerts");
        assertThrows(IllegalArgumentException.class, () -> new Ntfy(noUrl));
        NotificationProperties badTopic = props("NTFY_URL=https://n.example", "NTFY_TOPIC=a/b");
        assertThrows(IllegalArgumentException.class, () -> new Ntfy(badTopic));
        NotificationProperties badPriority = props("NTFY_URL=https://n.example", "NTFY_PRIORITY_ALERT=loud");
        assertThrows(IllegalArgumentException.class, () -> new Ntfy(badPriority));
    }

    @Test
    public void nonAsciiHeadersAreEncodedWords() {
        assertEquals("plain", Ntfy.headerValue("plain"));
        assertTrue(Ntfy.headerValue("서버").startsWith("=?UTF-8?B?"));
        assertEquals("a b", Ntfy.headerValue("a\r\nb"));
    }
}
