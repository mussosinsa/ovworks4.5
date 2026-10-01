package org.ovirt.engine.core.sso.api;

import org.ovirt.engine.core.uutils.security.ClientSerialCheck.Refusal;

/** A request turned away because it did not come from a registered terminal. */
public class ClientSerialRejectedException extends OAuthException {
    private static final long serialVersionUID = 2874460397164720881L;

    private final Refusal refusal;

    public ClientSerialRejectedException(Refusal refusal) {
        super(SsoConstants.ERR_CODE_UNAUTHORIZED_CLIENT, messageOf(refusal));
        this.refusal = refusal;
    }

    public Refusal getRefusal() {
        return refusal;
    }

    /** The words the client is answered with; the same ones the earlier check used. */
    private static String messageOf(Refusal refusal) {
        switch (refusal) {
        case MISSING:
            return "Missing X-Client-Serial header"; //$NON-NLS-1$
        case INVALID:
            return "Invalid client serial number"; //$NON-NLS-1$
        default:
            return "Client serial number cannot be verified"; //$NON-NLS-1$
        }
    }
}
