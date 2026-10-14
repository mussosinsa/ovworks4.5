package org.ovirt.engine.core.aaa.filters;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DedicatedIpWebPortalFilterTest {

    private static final String USER_ADDRESS = "192.0.2.92"; //$NON-NLS-1$
    private static final String TERMINAL_ADDRESS = "192.0.2.50"; //$NON-NLS-1$

    private final List<String> asked = new ArrayList<>();
    private Boolean engineAnswer;
    private long now = 1_000_000;

    private final DedicatedIpWebPortalFilter filter = new DedicatedIpWebPortalFilter() {
        @Override
        protected Boolean askEngine(String address) {
            asked.add(address);
            return USER_ADDRESS.equals(address) ? engineAnswer : Boolean.FALSE;
        }

        @Override
        protected long now() {
            return now;
        }
    };

    private HttpServletResponse response;
    private FilterChain chain;

    @BeforeEach
    public void setUp() throws IOException {
        engineAnswer = Boolean.TRUE;
        response = mock(HttpServletResponse.class);
        when(response.getOutputStream()).thenReturn(mock(ServletOutputStream.class));
        chain = mock(FilterChain.class);
    }

    private HttpServletRequest from(String address) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn(address);
        when(request.getRequestURI()).thenReturn("/ovirt-engine/webadmin/"); //$NON-NLS-1$
        return request;
    }

    @Test
    public void aUsersDedicatedAddressGetsTheForbiddenPage() throws IOException, ServletException {
        HttpServletRequest request = from(USER_ADDRESS);
        filter.doFilter(request, response, chain);
        verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    public void anyOtherAddressGoesOn() throws IOException, ServletException {
        HttpServletRequest request = from(TERMINAL_ADDRESS);
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
        verify(response, never()).setStatus(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    public void theEngineHostItselfIsNeverAsked() throws IOException, ServletException {
        HttpServletRequest request = from("127.0.0.1"); //$NON-NLS-1$
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
        assertEquals(List.of(), asked);
    }

    @Test
    public void theAnswerIsKeptForAWhileThenAskedAgain() {
        filter.isDenied(USER_ADDRESS);
        filter.isDenied(USER_ADDRESS);
        assertEquals(1, asked.size());
        now += DedicatedIpWebPortalFilter.ANSWER_MILLIS + 1;
        engineAnswer = Boolean.FALSE;
        assertEquals(false, filter.isDenied(USER_ADDRESS));
        assertEquals(2, asked.size());
    }

    @Test
    public void aQuestionTheEngineCannotAnswerLetsTheRequestThrough() throws IOException, ServletException {
        engineAnswer = null;
        HttpServletRequest request = from(USER_ADDRESS);
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
        // Not kept: the next request asks again.
        filter.isDenied(USER_ADDRESS);
        assertEquals(2, asked.size());
    }
}
