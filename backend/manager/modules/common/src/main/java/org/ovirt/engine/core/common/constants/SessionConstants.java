package org.ovirt.engine.core.common.constants;

public class SessionConstants {

    public static final String HTTP_SESSION_ENGINE_SESSION_ID_KEY = "ovirt_aaa_engineSessionId";
    public static final String SSO_AUTHENTICATION_ERR_MSG = "sso_auth_err_msg";
    public static final String SSO_TOKEN_KEY = "sso_token";
    public static final String SSO_SCOPE_KEY = "scope";
    public static final String SSO_REQUEST_ID = "request_id";
    public static final String UI_SSO_TOKEN_KEY = "UI_sso_token";

    /**
     * Response header naming why a session ended, on the reply that tells a client its session is
     * over. Its values are the wire names of
     * {@code org.ovirt.engine.core.common.businessentities.aaa.SessionEndReason}.
     */
    public static final String SESSION_END_REASON_HEADER = "X-OVirt-Session-End-Reason";

    /**
     * Request attribute holding the engine session id a request arrived carrying, put there before
     * anything can invalidate the HTTP session that held it. It is what lets a request that is
     * about to be refused say which session was refused, and so why.
     */
    public static final String REQUEST_PRESENTED_ENGINE_SESSION_ID = "ovirt_presented_engine_session_id";

}
