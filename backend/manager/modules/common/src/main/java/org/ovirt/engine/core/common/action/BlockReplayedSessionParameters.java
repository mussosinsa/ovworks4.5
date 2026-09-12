package org.ovirt.engine.core.common.action;

/**
 * Asks whether a request presenting this HTTP session identifier is a copy of one taken before the
 * session ended, and records it when it is.
 *
 * <p>The identifier is the whole of what the engine is given to judge by, which is also the whole
 * of what such a request carries: a cookie naming a session that no longer exists. Where the
 * request came from and what it asked for are passed so the audit entry can say so - they are
 * reported, never trusted.</p>
 */
public class BlockReplayedSessionParameters extends ActionParametersBase {

    private static final long serialVersionUID = 5455091318893377829L;

    private String httpSessionId;

    private String sourceIp;

    private String requestDescription;

    BlockReplayedSessionParameters() {
    }

    public BlockReplayedSessionParameters(String httpSessionId, String sourceIp, String requestDescription) {
        this.httpSessionId = httpSessionId;
        this.sourceIp = sourceIp;
        this.requestDescription = requestDescription;
    }

    public String getHttpSessionId() {
        return httpSessionId;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    /** Method and path of the refused request, for the audit entry. */
    public String getRequestDescription() {
        return requestDescription;
    }
}
