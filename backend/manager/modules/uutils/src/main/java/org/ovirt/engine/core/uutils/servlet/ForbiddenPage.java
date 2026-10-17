/*
 * Copyright 새올정보기술 (OV-Works), 2026
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.core.uutils.servlet;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The one page a browser is shown when the engine refuses or fails a request: the web server's own
 * "Forbidden" page, byte for byte.
 *
 * <p>The web server already answers a machine outside the terminal list with it. The engine used
 * to answer with the application server's bare pages instead - "Invalid client serial.",
 * "Internal Server Error" - which told the person at the browser which check had refused them and
 * that an application server sat behind the web server. Now every refusal and every failure looks
 * the same as the web server's, whichever layer it came from.</p>
 *
 * <p>Mapped as the error page of the browser-facing applications, it keeps the status the error
 * was raised with, so that a client reading the status still reads the right one; only the body
 * is replaced. {@link #send(HttpServletResponse)} is for a refusal, and answers 403.</p>
 */
public class ForbiddenPage extends HttpServlet {
    private static final long serialVersionUID = 6020361245216391752L;

    /** Apache httpd 2.4's own 403 page. */
    static final String HTML = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n" //$NON-NLS-1$
            + "<html><head>\n" //$NON-NLS-1$
            + "<title>403 Forbidden</title>\n" //$NON-NLS-1$
            + "</head><body>\n" //$NON-NLS-1$
            + "<h1>Forbidden</h1>\n" //$NON-NLS-1$
            + "<p>You don't have permission to access this resource.</p>\n" //$NON-NLS-1$
            + "</body></html>\n"; //$NON-NLS-1$

    static final String CONTENT_TYPE = "text/html; charset=iso-8859-1"; //$NON-NLS-1$

    private static final byte[] BODY = HTML.getBytes(StandardCharsets.ISO_8859_1);

    /**
     * Refuses the request with 403 and the page.
     *
     * <p>Written directly rather than through {@code sendError}: that would hand the response to
     * the application's error pages, and in the SSO application a 401 or an error page leads on into
     * the login flow - which is how a refused terminal used to end on "Internal Server Error".</p>
     */
    public static void send(HttpServletResponse response) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.resetBuffer();
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        write(response);
    }

    /**
     * As an error page: the status the error was raised with stays, the body is the page. Asked
     * for directly, it is a refusal like any other.
     */
    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        if (request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE) == null) {
            send(response);
            return;
        }
        if (response.isCommitted()) {
            return;
        }
        response.resetBuffer();
        write(response);
    }

    private static void write(HttpServletResponse response) throws IOException {
        response.setContentType(CONTENT_TYPE);
        response.setContentLength(BODY.length);
        response.setHeader("Cache-Control", "no-store"); //$NON-NLS-1$ //$NON-NLS-2$
        OutputStream out;
        try {
            out = response.getOutputStream();
        } catch (IllegalStateException e) {
            // What failed had already taken the writer.
            response.getWriter().write(HTML);
            response.getWriter().flush();
            return;
        }
        out.write(BODY);
        out.flush();
    }
}
