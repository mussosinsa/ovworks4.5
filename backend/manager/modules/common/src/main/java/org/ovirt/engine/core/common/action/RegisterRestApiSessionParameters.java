package org.ovirt.engine.core.common.action;

/**
 * Tells the engine which HTTP session carries a REST session.
 *
 * <p>The engine issues a session and the servlet container issues the cookie that points at it,
 * and only the container knows which is which. A request replayed after the session ended presents
 * that cookie and nothing else - the HTTP session it named is gone by then, so there is no longer
 * anything on the request tying it to the session it came from. Recording the pair while both are
 * alive is what lets the engine recognise such a request later.</p>
 *
 * <p>Sent once, when the REST session is created.</p>
 */
public class RegisterRestApiSessionParameters extends ActionParametersBase {

    private static final long serialVersionUID = 4076159214428832216L;

    private String httpSessionId;

    RegisterRestApiSessionParameters() {
    }

    public RegisterRestApiSessionParameters(String engineSessionId, String httpSessionId) {
        super(engineSessionId);
        this.httpSessionId = httpSessionId;
    }

    public String getHttpSessionId() {
        return httpSessionId;
    }
}
