<%@ page pageEncoding="UTF-8" session="true" %>
<%@ page import="org.ovirt.engine.core.sso.api.SsoConstants" %>
<%@ page import="org.ovirt.engine.core.sso.api.SsoSession" %>
<%@ page import="org.ovirt.engine.core.sso.service.LoginFormNonce" %>
<%@ page import="org.ovirt.engine.core.sso.utils.LoginEnvelopeCrypto" %>
<%@ page import="org.ovirt.engine.core.uutils.security.LoginInputPolicy" %>
<%@ page import="java.util.logging.Level" %>
<%@ page import="java.util.logging.Logger" %>

<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="obrand" uri="obrand" %>
<%@ taglib prefix="sso" tagdir="/WEB-INF/tags" %>

<fmt:setLocale value="${locale}" />
<fmt:setBundle basename="sso-messages" var="loginpage" />
<sso:getContext var="ssoContext" locale="ssoLocale" />
<sso:getSession var="ssoSession" />
<%
    Logger logger = Logger.getLogger("org.ovirt.engine.sso.login");
    String loginEncryptionPublicKey;
    try {
        loginEncryptionPublicKey = LoginEnvelopeCrypto.readRsaPublicKey();
    } catch (Exception ex) {
        loginEncryptionPublicKey = ""; //$NON-NLS-1$
        logger.log(Level.WARNING, "Unable to read login encryption RSA public key.", ex);
    }
    pageContext.setAttribute("loginEncryptionPublicKey", loginEncryptionPublicKey); //$NON-NLS-1$

    // Good for one login from this rendering of the page. The password is encrypted together with
    // it, so a copy of the request cannot log in again: see LoginFormNonce.
    SsoSession loginFormSession = (SsoSession) pageContext.getAttribute("ssoSession"); //$NON-NLS-1$
    if (loginFormSession != null) {
        pageContext.setAttribute("loginFormNonce", LoginFormNonce.issue(loginFormSession)); //$NON-NLS-1$
        pageContext.setAttribute("loginFormIssuedAt", System.currentTimeMillis() / 1000L); //$NON-NLS-1$
    }

    // What the ID and the password may hold - the rules the server checks again. Written for the
    // script below, which refuses as the user types what the server would refuse after a submit.
    pageContext.setAttribute("loginInputPolicy", LoginInputPolicy.toJson()); //$NON-NLS-1$
    pageContext.setAttribute("loginInputMaxLength", LoginInputPolicy.MAX_LENGTH); //$NON-NLS-1$
%>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <obrand:favicon />
    <title>
        <fmt:message key="product" />
        <fmt:message key="loginpage.title" bundle="${loginpage}" />
    </title>
    <obrand:stylesheets />
    <obrand:javascripts />
    <script src="retain-fragment.js" type="text/javascript"></script>
    <script type="application/json" id="loginInputPolicy">${loginInputPolicy}</script>
    <script type="text/javascript">
    (function () {
        function normalizePublicKey(key) {
            if (!key) {
                return null;
            }

            var trimmed = key.trim();
            if (!trimmed) {
                return null;
            }

            if (trimmed.indexOf('BEGIN PUBLIC KEY') === -1) {
                var lines = trimmed.match(/.{1,64}/g) || [];
                trimmed = '-----BEGIN PUBLIC KEY-----\n' + lines.join('\n') + '\n-----END PUBLIC KEY-----';
            }

            return trimmed;
        }

        function pemToArrayBuffer(pem) {
            var base64 = pem.replace(/-----BEGIN PUBLIC KEY-----/g, '')
                .replace(/-----END PUBLIC KEY-----/g, '')
                .replace(/\s+/g, '');
            var binary = window.atob(base64);
            var bytes = new Uint8Array(binary.length);

            for (var i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }

            return bytes.buffer;
        }

        function arrayBufferToBase64(buffer) {
            var bytes = new Uint8Array(buffer);
            var binary = '';

            for (var i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }

            return window.btoa(binary);
        }

        async function encryptText(publicKey, value) {
            var encrypted = await window.crypto.subtle.encrypt(
                { name: 'RSA-OAEP' },
                publicKey,
                new TextEncoder().encode(value)
            );

            return arrayBufferToBase64(encrypted);
        }

        async function encryptAndSubmit(form) {
            var publicKeyValue = normalizePublicKey(document.getElementById('loginPublicKey').value);

            if (!publicKeyValue) {
                throw new Error('LOGIN_ENCRYPTION_PUBLIC_KEY_MISSING');
            }

            if (!window.crypto || !window.crypto.subtle) {
                throw new Error('LOGIN_ENCRYPTION_WEBCRYPTO_UNAVAILABLE');
            }

            var publicKey = await window.crypto.subtle.importKey(
                'spki',
                pemToArrayBuffer(publicKeyValue),
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                false,
                ['encrypt']
            );
            var usernameField = document.getElementById('username');
            var passwordField = document.getElementById('password');

            document.getElementById('encryptedUsername').value = await encryptText(publicKey, usernameField.value);
            // The same wrapper a REST client puts around its password, with the nonce the server
            // issued for this page in place of one of the browser's own. The timestamp is the
            // server's, from when the page was rendered; it is not checked, so a page left open
            // still logs in, and the browser's clock does not matter.
            var loginFormNonce = document.getElementById('loginFormNonce').value;
            var loginFormIssuedAt = document.getElementById('loginFormIssuedAt').value;
            if (!loginFormNonce) {
                throw new Error('LOGIN_FORM_NONCE_MISSING');
            }
            var wrappedPassword = 'ovirt-login:v1:' + loginFormIssuedAt + ':' + loginFormNonce + ':'
                    + passwordField.value;
            document.getElementById('encryptedPassword').value = await encryptText(publicKey, wrappedPassword);

            usernameField.value = '';
            passwordField.value = '';
            form.submit();
        }

        // The ID and password rules of LoginInputPolicy, written into the page by the server.
        // Without them the fields are left as they are: the server checks again either way.
        function loadLoginInputPolicy() {
            var element = document.getElementById('loginInputPolicy');
            if (!element) {
                return null;
            }
            try {
                var policy = JSON.parse(element.textContent);
                policy.patterns = policy.sqlInjection.map(function (pattern) {
                    return new RegExp(pattern, 'i');
                });
                return policy;
            } catch (error) {
                return null;
            }
        }

        // Blanks of every kind and control characters, as Java's isWhitespace/isSpaceChar/isISOControl.
        var BLANK_OR_CONTROL = /[\s\u0000-\u001f\u007f-\u009f]/;

        function isForbiddenCharacter(policy, field, character) {
            return policy.forbidden.indexOf(character) >= 0
                    || BLANK_OR_CONTROL.test(character)
                    || (field === 'USER_NAME' && policy.userNameForbidden.indexOf(character) >= 0);
        }

        // The first problem, in the order the server checks them, or null.
        function checkLoginInput(policy, field, value) {
            if (!value) {
                return null;
            }
            if (value.length > policy.maxLength) {
                return 'TOO_LONG';
            }
            for (var i = 0; i < value.length; i++) {
                if (isForbiddenCharacter(policy, field, value.charAt(i))) {
                    return 'FORBIDDEN_CHARACTER';
                }
            }
            for (var j = 0; j < policy.patterns.length; j++) {
                if (policy.patterns[j].test(value)) {
                    return 'SQL_INJECTION';
                }
            }
            return null;
        }

        function showLoginInputError(input, message) {
            var error = document.getElementById(input.id + 'InputError');
            if (!error) {
                return;
            }
            error.textContent = message || '';
            error.hidden = !message;
            error.style.display = message ? '' : 'none';
            if (message) {
                input.setAttribute('aria-invalid', 'true');
            } else {
                input.removeAttribute('aria-invalid');
            }
        }

        // Characters that may not be typed never get into the field: they are taken out as they
        // arrive, typed or pasted, and the user is told why. So is what is past the length limit.
        function guardLoginInput(policy, input, field) {
            input.addEventListener('input', function () {
                var value = input.value;
                var caret = typeof input.selectionStart === 'number' ? input.selectionStart : value.length;
                var kept = '';
                var removedBeforeCaret = 0;
                for (var i = 0; i < value.length; i++) {
                    if (isForbiddenCharacter(policy, field, value.charAt(i))) {
                        if (i < caret) {
                            removedBeforeCaret++;
                        }
                    } else {
                        kept += value.charAt(i);
                    }
                }
                var problem = null;
                if (kept.length !== value.length) {
                    problem = 'FORBIDDEN_CHARACTER';
                }
                if (kept.length > policy.maxLength) {
                    kept = kept.substring(0, policy.maxLength);
                    problem = problem || 'TOO_LONG';
                }
                if (kept !== value) {
                    input.value = kept;
                    var position = Math.min(caret - removedBeforeCaret, kept.length);
                    try {
                        input.setSelectionRange(position, position);
                    } catch (error) {
                        // not every input type has a selection
                    }
                }
                showLoginInputError(input, problem ? policy.messages[field][problem] : '');
            });
        }

        document.addEventListener('DOMContentLoaded', function () {
            var form = document.getElementById('loginForm');

            if (!form) {
                return;
            }

            var loginInputPolicy = loadLoginInputPolicy();
            var loginInputs = [
                { input: document.getElementById('username'), field: 'USER_NAME' },
                { input: document.getElementById('password'), field: 'PASSWORD' }
            ].filter(function (entry) {
                return entry.input;
            });
            if (loginInputPolicy) {
                loginInputs.forEach(function (entry) {
                    guardLoginInput(loginInputPolicy, entry.input, entry.field);
                });
            }

            form.addEventListener('submit', function (event) {
                if (form.dataset.encrypting === 'true') {
                    return;
                }

                event.preventDefault();
                // The password is checked as typed, before it is wrapped for encryption.
                if (loginInputPolicy) {
                    for (var i = 0; i < loginInputs.length; i++) {
                        var entry = loginInputs[i];
                        var problem = checkLoginInput(loginInputPolicy, entry.field, entry.input.value);
                        showLoginInputError(entry.input, problem ? loginInputPolicy.messages[entry.field][problem] : '');
                        if (problem) {
                            entry.input.focus();
                            return;
                        }
                    }
                }
                form.dataset.encrypting = 'true';
                encryptAndSubmit(form).catch(function (error) {
                    form.dataset.encrypting = 'false';
                    if (window.console && window.console.error) {
                        window.console.error('Login encryption failed before submit.', error);
                    }

                    if (error && error.message === 'LOGIN_ENCRYPTION_PUBLIC_KEY_MISSING') {
                        window.alert('로그인 암호화 키를 불러오지 못했습니다. 관리자에게 문의하세요.');
                    } else if (error && error.message === 'LOGIN_FORM_NONCE_MISSING') {
                        window.alert('로그인 화면이 만료되었습니다. 화면을 새로 고친 뒤 다시 로그인해 주세요.');
                    } else if (error && error.message === 'LOGIN_ENCRYPTION_WEBCRYPTO_UNAVAILABLE') {
                        window.alert('현재 브라우저에서 로그인 암호화를 지원하지 않습니다. 최신 브라우저를 사용해 주세요.');
                    } else {
                        window.alert('로그인 정보 암호화에 실패했습니다. 관리자에게 문의하세요.');
                    }
                });
            });
        });
    }());
    </script>
</head>
<body class="ovirt-container">
    <c:if test="${ssoSession.status == 'authenticated'}">
        <c:redirect url="/interactive-login" />
    </c:if>

    <c:if test="${ssoSession.clientId == null}">
        <c:redirect url="${ssoContext.engineUrl}" />
    </c:if>

    <c:if test="${ssoSession.reauthenticate == true}">
        <c:redirect
            url="/oauth/authorize?client_id=${ssoSession.clientId}&response_type=code&scope=${ssoSession.scope}&app_url=${ssoSession.appUrl}&redirect_uri=${ssoSession.redirectUri}?" />
    </c:if>

    <c:set target="${ssoSession}" property="reauthenticate" value="true" />

    <obrand:background-image />

    <div class="pf-c-login">
        <div class="pf-c-login__container">

            <header class="pf-c-login__header">
                <a href="${ssoContext.engineUrl}" class="pf-c-brand obrand_loginPageLogoLink">
                    <div class="obrand_loginPageLogo"></div>
                </a>
            </header>

            <main class="pf-c-login__main">
                <header class="pf-c-login__main-header">
                    <h1 class="pf-c-title pf-m-3xl">
                        <fmt:message key="loginpage.title" bundle="${loginpage}" />
                    </h1>
                </header>

                <div class="pf-c-login__main-body">
                    <form
                        novalidate class="pf-c-form" id="loginForm"
                        method="post"
                        action="${pageContext.request.contextPath}/interactive-login"
                    >
                        <p class="pf-c-form__helper-text pf-m-error">
                            <c:if test="${ssoSession.loginMessage != null && ssoSession.loginMessage != '' }">
                                <i class="fas fa-exclamation-circle pf-c-form__helper-text-icon"></i>
                                <c:out value="${ssoSession.loginMessage}"/>
                                <c:set target="${ssoSession}" property="loginMessage" value="" />
                            </c:if>
                        </p>

                        <c:if test="${ssoSession.loginErrorCode != null && ssoSession.loginErrorCode == SsoConstants.APP_ERROR_USER_PASSWORD_EXPIRED_CHANGE_URL_PROVIDED}">
                            <a href="${ssoContext.changePasswordUrl}"><fmt:message key="loginpage.changepasswordlink" bundle="${loginpage}" /></a>
                            <c:set target="${ssoSession}" property="loginErrorCode" value="" />
                        </c:if>

                        <input type="hidden" id="loginPublicKey" value="${fn:escapeXml(loginEncryptionPublicKey)}">
                        <input type="hidden" id="encryptedUsername" name="encryptedUsername">
                        <input type="hidden" id="encryptedPassword" name="encryptedPassword">
                        <input type="hidden" id="loginFormNonce" value="${fn:escapeXml(loginFormNonce)}">
                        <input type="hidden" id="loginFormIssuedAt" value="${fn:escapeXml(loginFormIssuedAt)}">

                        <input
                            type="hidden" class="pf-c-form-control" id="sessionIdToken"
                            placeholder="sessionIdToken"
                            name="sessionIdToken"
                            value="${ssoSession.sessionIdToken}"
                        >

                        <div class="pf-form__group">
                            <label class="pf-c-form__label-text" for="username">
                                <fmt:message key="loginpage.username" bundle="${loginpage}" />
                            </label>
                            <input type="text" id="username" name="username" class="pf-c-form-control" autofocus tabIndex="1"
                                maxlength="${loginInputMaxLength}" autocomplete="username" aria-describedby="usernameInputError">
                            <p class="pf-c-form__helper-text pf-m-error" id="usernameInputError" aria-live="polite" hidden style="display: none"></p>
                        </div>
                        <div class="pf-form__group">
                            <label class="pf-c-form__label-text" for="password">
                                <fmt:message key="loginpage.password" bundle="${loginpage}" />
                            </label>
                            <input type="password" class="pf-c-form-control" id="password" name="password" tabIndex="2"
                                maxlength="${loginInputMaxLength}" autocomplete="current-password" aria-describedby="passwordInputError">
                            <p class="pf-c-form__helper-text pf-m-error" id="passwordInputError" aria-live="polite" hidden style="display: none"></p>
                        </div>
                        <div class="pf-form__group">
                            <label class="pf-c-form__label-text" for="profile">
                                <fmt:message key="loginpage.profile" bundle="${loginpage}" />
                            </label>
                            <select class="pf-c-form-control" id="profile" name="profile" tabIndex="3">
                                <c:forEach
                                    items="${ssoContext.ssoProfilesSupportingPasswd}"
                                    var="profile"
                                >
                                    <c:choose>
                                        <c:when test="${cookie['profile'] != null && cookie['profile'].value == profile}">
                                            <option value="${profile}" selected>${profile}</option>
                                        </c:when>
                                        <c:otherwise>
                                            <option value="${profile}">${profile}</option>
                                        </c:otherwise>
                                    </c:choose>
                                </c:forEach>
                            </select>
                        </div>

                        <div class="pf-c-form__group pf-m-action">
                            <button class="pf-c-button pf-m-primary pf-m-block" type="submit">
                                <fmt:message key="loginpage.login" bundle="${loginpage}" />
                            </button>
                        </div>
                    </form>

                    <c:if test="${fn:length(ssoSession.authStack) gt 0}">
                        <div class="pull-right">
                            <form
                                class="form-horizontal"
                                method="post"
                                action="${pageContext.request.contextPath}/interactive-login-next-auth"
                                enctype="application/x-www-form-urlencoded"
                            >
                                <button type="submit" class="btn btn-primary btn-lg" tabIndex="5">
                                    <fmt:message key="loginpage.nextauth" bundle="${loginpage}" />
                                </button>
                                <span>&nbsp;</span>
                            </form>
                        </div>
                    </c:if>
                </div>
            </main>

            <footer class="pf-c-login__footer">
                <p class="obrand_loginPageSubtitle">
                    <fmt:message key="obrand.loginpage.subtitle" />
                </p>
            </footer>
        </div>
    </div>
</body>
</html>
