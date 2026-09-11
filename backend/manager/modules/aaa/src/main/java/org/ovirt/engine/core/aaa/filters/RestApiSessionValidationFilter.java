package org.ovirt.engine.core.aaa.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.ovirt.engine.core.common.constants.SessionConstants;

public class RestApiSessionValidationFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        int prefer = FiltersHelper.getPrefer(req);
        if ((prefer & FiltersHelper.PREFER_NEW_AUTH) != 0 || (prefer & FiltersHelper.PREFER_PERSISTENCE_AUTH) == 0) {
            HttpSession session = req.getSession(false);
            if (session != null) {
                // The HTTP session is only the pointer; the session itself is held by the engine
                // and outlives it. Dropping the pointer without ending the session left it open
                // until its idle timeout ran out, reachable by nobody - a login that looked over
                // and was not.
                FiltersHelper.logoutEngineSession(
                        (String) session.getAttribute(SessionConstants.HTTP_SESSION_ENGINE_SESSION_ID_KEY));
                try {
                    session.invalidate();
                } catch (IllegalStateException e) {
                    // ignore
                }
            }
        }
        chain.doFilter(request, response);

    }

    @Override
    public void destroy() {
    }

}
