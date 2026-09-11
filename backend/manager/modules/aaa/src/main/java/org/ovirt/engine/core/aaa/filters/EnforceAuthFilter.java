package org.ovirt.engine.core.aaa.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.common.businessentities.aaa.SessionEndReason;
import org.ovirt.engine.core.common.constants.SessionConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EnforceAuthFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(EnforceAuthFilter.class);

    private final List<String> additionalSchemes = new ArrayList<>();

    @Override
    public void init(FilterConfig filterConfig) {
        for (String paramName : Collections.list(filterConfig.getInitParameterNames())) {
            if (paramName.startsWith("scheme")) {
                additionalSchemes.add(filterConfig.getInitParameter(paramName));
            }
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {
        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse)response;

        if (FiltersHelper.isAuthenticated(req)) {
            chain.doFilter(request, response);
        } else {
            @SuppressWarnings("unchecked")
            List<String> schemes = (List<String>) req.getAttribute(FiltersHelper.Constants.REQUEST_SCHEMES_KEY);
            if (schemes == null) {
                schemes = Collections.emptyList();
            }
            Set<String> allSchemes = new HashSet<>(schemes);
            allSchemes.addAll(additionalSchemes);
            for (String scheme: allSchemes) {
                res.setHeader(FiltersHelper.Constants.HEADER_WWW_AUTHENTICATE, scheme);
            }
            if (Boolean.TRUE.equals(req.getAttribute(FiltersHelper.Constants.HEADER_PASSWORD_CHANGE_REQUIRED))) {
                res.setHeader(FiltersHelper.Constants.HEADER_PASSWORD_CHANGE_REQUIRED, "true");
                Object grantType = req.getAttribute(FiltersHelper.Constants.HEADER_PASSWORD_CHANGE_GRANT_TYPE);
                if (grantType != null) {
                    res.setHeader(FiltersHelper.Constants.HEADER_PASSWORD_CHANGE_GRANT_TYPE, grantType.toString());
                }
            }
            reportSessionEndReason(req, res);
            String errMsg = (String) req.getAttribute(SessionConstants.SSO_AUTHENTICATION_ERR_MSG);
            if (StringUtils.isEmpty(errMsg)) {
                res.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            } else {
                res.sendError(HttpServletResponse.SC_UNAUTHORIZED, errMsg);
            }
        }

    }

    /**
     * Says why a request carrying a session is being refused, when the reason is that the session
     * ended.
     *
     * <p>Without this a client learns only that it is no longer authenticated, and the two things
     * a user needs to be told apart - an administrator ended my session, or it timed out - look
     * identical. It could ask afterwards, but by the time it is refused the HTTP session that held
     * the session id has been dropped, so asking would only get "there is no session": the answer
     * has to travel on the refusal itself.</p>
     *
     * <p>Only a request that arrived carrying a session is answered this way. One that presented
     * credentials that did not work is a failed login, not an ended session, and gets nothing here
     * to be mistaken for one.</p>
     *
     * <p>The lookup happens only on the way to a 401, so the common path pays nothing for it, and
     * a lookup that fails is dropped rather than guessed at.</p>
     */
    private void reportSessionEndReason(HttpServletRequest req, HttpServletResponse res) {
        String engineSessionId =
                (String) req.getAttribute(SessionConstants.REQUEST_PRESENTED_ENGINE_SESSION_ID);
        if (StringUtils.isEmpty(engineSessionId)) {
            return;
        }
        try {
            SessionEndReason reason = FiltersHelper.sessionEndReason(engineSessionId);
            if (reason != null) {
                res.setHeader(SessionConstants.SESSION_END_REASON_HEADER, reason.getWireName());
            }
        } catch (RuntimeException e) {
            // The refusal stands either way; only the explanation is lost.
            log.warn("Unable to report why a session ended: {}", e.getMessage());
            log.debug("Exception", e);
        }
    }

    @Override
    public void destroy() {
    }

}
