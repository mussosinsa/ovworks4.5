/*
 * Copyright 새올정보기술 (OV-Works), 2026
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.core.uutils.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;

class ForbiddenPageTest {

    private final ByteArrayOutputStream written = new ByteArrayOutputStream();
    private final HttpServletResponse response = mock(HttpServletResponse.class);

    ForbiddenPageTest() throws IOException {
        when(response.getOutputStream()).thenReturn(new ServletOutputStream() {
            @Override
            public void write(int b) {
                written.write(b);
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener writeListener) {
            }
        });
    }

    @Test
    void theRefusalIsTheWebServersOwnForbiddenPage() throws IOException {
        ForbiddenPage.send(response);
        verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verify(response).setContentType("text/html; charset=iso-8859-1");
        String page = written.toString(StandardCharsets.ISO_8859_1);
        assertTrue(page.contains("<title>403 Forbidden</title>"));
        assertTrue(page.contains("<h1>Forbidden</h1>"));
        assertTrue(page.contains("<p>You don't have permission to access this resource.</p>"));
    }

    @Test
    void nothingOfWhatWasRefusedOrWhyIsShown() {
        for (String leak : new String[] { "client serial", "Internal Server Error", "Error", "WildFly",
                "Undertow" }) {
            assertTrue(!ForbiddenPage.HTML.contains(leak), leak);
        }
    }

    @Test
    void asAnErrorPageTheStatusOfTheErrorIsKept() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE)).thenReturn(500);
        new ForbiddenPage().service(request, response);
        verify(response, never()).setStatus(HttpServletResponse.SC_FORBIDDEN);
        assertEquals(ForbiddenPage.HTML, written.toString(StandardCharsets.ISO_8859_1));
    }

    @Test
    void askedForDirectlyItIsARefusal() throws Exception {
        new ForbiddenPage().service(mock(HttpServletRequest.class), response);
        verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
        assertEquals(ForbiddenPage.HTML, written.toString(StandardCharsets.ISO_8859_1));
    }

    @Test
    void aResponseAlreadySentIsLeftAlone() throws IOException {
        when(response.isCommitted()).thenReturn(true);
        ForbiddenPage.send(response);
        verify(response, never()).setStatus(HttpServletResponse.SC_FORBIDDEN);
        assertEquals(0, written.size());
    }
}
