package org.ovirt.engine.core.common.action;

/**
 * Tells the engine which HTTP session carries an engine session.
 *
 * <p>The engine issues a session and the servlet container issues the cookie that points at it,
 * and only the container knows which is which. A request replayed after the session ended presents
 * that cookie and nothing else - the HTTP session it named is gone by then, so there is no longer
 * anything on the request tying it to the session it came from. Recording the pair while both are
 * alive is what lets the engine recognise such a request later.</p>
 *
 * <p>Sent once, when the session is created: by the filter that manages a REST session,
 * and by the servlet that signs a browser in. Both, because a copy of a browser's traffic
 * is the same copy as a copy of an API client's, and only a pair that was recorded can be
 * recognised afterwards.</p>
 */
public class RegisterHttpSessionParameters extends ActionParametersBase {

    private static final long serialVersionUID = 4076159214428832216L;

    private String httpSessionId;

    RegisterHttpSessionParameters() {
    }

    public RegisterHttpSessionParameters(String engineSessionId, String httpSessionId) {
        super(engineSessionId);
        this.httpSessionId = httpSessionId;
    }

    public String getHttpSessionId() {
        return httpSessionId;
    }
}
