package org.ovirt.engine.core.sso.service;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.ovirt.engine.api.extensions.ExtMap;
import org.ovirt.engine.api.extensions.aaa.Authn;
import org.ovirt.engine.core.sso.api.SsoConstants;
import org.ovirt.engine.core.sso.api.SsoContext;

public class AuthnMessageMapper {
    private static final Map<Integer, String> messagesMap = new HashMap<>();

    static {
        messagesMap.put(Authn.AuthResult.GENERAL_ERROR, SsoConstants.APP_ERROR_USER_FAILED_TO_AUTHENTICATE);
        messagesMap.put(Authn.AuthResult.CREDENTIALS_INVALID,
                SsoConstants.APP_ERROR_USER_FAILED_TO_AUTHENTICATE);
        messagesMap.put(Authn.AuthResult.CREDENTIALS_INCORRECT,
                SsoConstants.APP_ERROR_USER_FAILED_TO_AUTHENTICATE);
        messagesMap.put(Authn.AuthResult.ACCOUNT_LOCKED, SsoConstants.APP_ERROR_USER_ACCOUNT_DISABLED);
        messagesMap.put(Authn.AuthResult.ACCOUNT_DISABLED, SsoConstants.APP_ERROR_USER_ACCOUNT_DISABLED);
        messagesMap.put(Authn.AuthResult.ACCOUNT_EXPIRED, SsoConstants.APP_ERROR_USER_ACCOUNT_EXPIRED);
        messagesMap.put(Authn.AuthResult.TIMED_OUT, SsoConstants.APP_ERROR_USER_FAILED_TO_AUTHENTICATE_TIMED_OUT);
        messagesMap.put(Authn.AuthResult.CREDENTIALS_EXPIRED,
                SsoConstants.APP_ERROR_USER_PASSWORD_EXPIRED_CHANGE_URL_PROVIDED);
    }

    public static final String mapErrorCode(
            SsoContext ssoContext,
            HttpServletRequest request,
            String profile,
            ExtMap outputMap) {
        int authResult = outputMap.<Integer>get(Authn.InvokeKeys.RESULT);
        String errorCode = messagesMap.containsKey(authResult)
                ? messagesMap.get(authResult)
                : SsoConstants.APP_ERROR_USER_FAILED_TO_AUTHENTICATE;

        if (authResult == Authn.AuthResult.CREDENTIALS_EXPIRED) {
            if (outputMap.<String> get(Authn.InvokeKeys.CREDENTIALS_CHANGE_URL) != null ||
                    SsoService.getSsoContext(request).getSsoProfilesSupportingPasswdChange().contains(profile)) {
                errorCode = SsoConstants.APP_ERROR_USER_PASSWORD_EXPIRED_CHANGE_URL_PROVIDED;
            } else {
                errorCode = SsoConstants.APP_ERROR_USER_PASSWORD_EXPIRED;
            }
        }

        return errorCode;
    }

    /**
     * Works out what to tell a user whose password change the authentication provider refused.
     *
     * <p>The provider says why in {@code Base.InvokeKeys.MESSAGE}, and until this existed nobody
     * read it: every refusal reached the user as "contact your administrator", which is no help at
     * all to the administrator changing their own password on a first login, and no help to a user
     * who only mistyped the password they already have. The rules a change can break are few and
     * known, so each is recognised here and answered in the user's language.</p>
     *
     * <p>The provider's own wording is never shown. It is written for a log, it is not translated,
     * and on an unexpected failure it carries whatever the exception said - which can name tables,
     * files, or hosts. Anything not recognised therefore falls back to the caller's general
     * message rather than being passed through.</p>
     *
     * @param providerMessage what the provider reported, may be null
     * @return the message key to show, or null when the reason is not one that can be shown
     */
    public static String mapCredentialsChangeDetail(String providerMessage) {
        if (providerMessage == null) {
            return null;
        }
        String reason = providerMessage.toLowerCase(Locale.ROOT);

        // the password the user typed as their current one
        if (reason.contains("credentials incorrect")) { //$NON-NLS-1$
            return SsoConstants.APP_ERROR_CHANGE_PASSWORD_CURRENT_INCORRECT;
        }
        // reuse, of the password in force or of one in the history
        if (reason.contains("already used")) { //$NON-NLS-1$
            return SsoConstants.APP_ERROR_CHANGE_PASSWORD_ALREADY_USED;
        }
        if (reason.contains("too short")) { //$NON-NLS-1$
            return SsoConstants.APP_ERROR_CHANGE_PASSWORD_TOO_SHORT;
        }
        if (reason.contains("identical to the user id")) { //$NON-NLS-1$
            return SsoConstants.APP_ERROR_CHANGE_PASSWORD_SAME_AS_USER_ID;
        }
        if (reason.contains("special character")) { //$NON-NLS-1$
            return SsoConstants.APP_ERROR_CHANGE_PASSWORD_NO_SPECIAL;
        }
        // both of the provider's sequence rules, which it words differently
        if (reason.contains("consecutive characters")) { //$NON-NLS-1$
            return SsoConstants.APP_ERROR_CHANGE_PASSWORD_SEQUENTIAL;
        }
        if (reason.contains("repeated characters")) { //$NON-NLS-1$
            return SsoConstants.APP_ERROR_CHANGE_PASSWORD_REPEATED;
        }
        // what the provider prints when the configured character classes are not all present
        if (reason.contains("uppercase") || reason.contains("lowercase") || reason.contains("numbers")) { //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            return SsoConstants.APP_ERROR_CHANGE_PASSWORD_COMPLEXITY;
        }

        return null;
    }
}
