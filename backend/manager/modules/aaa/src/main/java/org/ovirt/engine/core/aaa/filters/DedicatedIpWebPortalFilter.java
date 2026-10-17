/*
 * Copyright 새올정보기술 (OV-Works), 2026
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.core.aaa.filters;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.naming.InitialContext;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.common.queries.NameQueryParameters;
import org.ovirt.engine.core.common.queries.QueryReturnValue;
import org.ovirt.engine.core.common.queries.QueryType;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck;
import org.ovirt.engine.core.uutils.servlet.ForbiddenPage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Refuses the web portal - the welcome page, the administration portal and the login pages - to an
 * address that is only a user's dedicated login address, with the web server's Forbidden page.
 *
 * <p>The engine decides, see IsWebPortalDeniedForAddressQuery: the address is the dedicated address
 * of users none of whom is an administrator. The client program's login over the REST API is not
 * behind this filter and goes on as before.</p>
 *
 * <p>A browser asks for dozens of resources for one page, so the answer for an address is kept for
 * {@link #ANSWER_MILLIS}: a change of dedicated address reaches the portal within that time. A
 * question the engine cannot answer lets the request through - the login itself still checks the
 * dedicated address, and refusing on a moment of trouble would lock every administrator out.</p>
 */
public class DedicatedIpWebPortalFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(DedicatedIpWebPortalFilter.class);

    static final long ANSWER_MILLIS = 30_000;
    private static final int MAX_ANSWERS = 1024;

    private final Map<String, Answer> answers = new ConcurrentHashMap<>();

    private static final class Answer {
        final boolean denied;
        final long until;

        Answer(boolean denied, long until) {
            this.denied = denied;
            this.until = until;
        }
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        String address = StringUtils.trimToNull(req.getRemoteAddr());
        if (address != null && !ClientSerialCheck.isThisHost(address) && isDenied(address)) {
            log.warn("웹 포털 접속 차단(사용자 전용 접속 IP); 출발지='{}'; 경로='{}'", address, req.getRequestURI());
            ForbiddenPage.send((HttpServletResponse) response);
            return;
        }
        chain.doFilter(request, response);
    }

    boolean isDenied(String address) {
        long now = now();
        Answer answer = answers.get(address);
        if (answer != null && answer.until > now) {
            return answer.denied;
        }
        Boolean denied = askEngine(address);
        if (denied == null) {
            return false;
        }
        if (answers.size() >= MAX_ANSWERS) {
            answers.clear();
        }
        answers.put(address, new Answer(denied, now + ANSWER_MILLIS));
        return denied;
    }

    /** @return the engine's answer, or null when it could not be had. Overridable for tests. */
    protected Boolean askEngine(String address) {
        try {
            InitialContext ctx = new InitialContext();
            try {
                QueryReturnValue result = FiltersHelper.getBackend(ctx).runPublicQuery(
                        QueryType.IsWebPortalDeniedForAddress, new NameQueryParameters(address));
                return result != null && result.getSucceeded() ? result.<Boolean> getReturnValue() : null;
            } finally {
                ctx.close();
            }
        } catch (Exception e) {
            log.error("Unable to ask whether the web portal is refused to {}: {}", address, e.getMessage());
            log.debug("Exception", e);
            return null;
        }
    }

    /** Overridable for tests. */
    protected long now() {
        return System.currentTimeMillis();
    }

    @Override
    public void destroy() {
    }
}
