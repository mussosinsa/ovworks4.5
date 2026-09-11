<%@ page pageEncoding="UTF-8" session="true" %>
<%@ page import="org.ovirt.engine.core.sso.utils.LoginEnvelopeCrypto" %>
<%@ page import="java.util.logging.Level" %>
<%@ page import="java.util.logging.Logger" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="obrand" uri="obrand" %>
<%@ taglib prefix="sso" tagdir="/WEB-INF/tags" %>

<fmt:setLocale value="${locale}" />
<fmt:setBundle basename="sso-messages" var="changepasswordpage" />
<sso:getContext var="ssoContext" locale="ssoLocale" />
<sso:getSession var="ssoSession" />
<%
    Logger changePasswordLogger = Logger.getLogger("org.ovirt.engine.sso.changepassword");
    String changeEncryptionPublicKey;
    try {
        changeEncryptionPublicKey = LoginEnvelopeCrypto.readRsaPublicKey();
    } catch (Exception ex) {
        changeEncryptionPublicKey = ""; //$NON-NLS-1$
        changePasswordLogger.log(Level.WARNING, "Unable to read the password change encryption RSA public key.", ex);
    }
    pageContext.setAttribute("changeEncryptionPublicKey", changeEncryptionPublicKey); //$NON-NLS-1$
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
        <fmt:message key="changepasswordpage.title" bundle="${changepasswordpage}" />
    </title>
    <obrand:stylesheets />
    <obrand:javascripts />
    <script type="text/javascript">
    //<![CDATA[
    (function () {
        // The same encryption the login form does, for the same reason: what this form carries is
        // the password in force and the one replacing it, together, which is more than a login
        // carries. It used to post all three in the clear while the login form behind it did not.
        //
        // The credentials are encrypted, not wrapped against replay the way a REST client's are.
        // The wrapper is checked against a freshness window, and this page is the only way past an
        // expired password: a browser whose clock is off by more than that window would be able to
        // log in and then unable to change the password it is being told to change. The login form
        // does not impose it either, so imposing it here alone is what would strand someone.
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
            var publicKeyValue = normalizePublicKey(document.getElementById('changePublicKey').value);

            if (!publicKeyValue) {
                throw new Error('CHANGE_ENCRYPTION_PUBLIC_KEY_MISSING');
            }

            if (!window.crypto || !window.crypto.subtle) {
                throw new Error('CHANGE_ENCRYPTION_WEBCRYPTO_UNAVAILABLE');
            }

            var publicKey = await window.crypto.subtle.importKey(
                'spki',
                pemToArrayBuffer(publicKeyValue),
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                false,
                ['encrypt']
            );
            var currentField = document.getElementById('credentials');
            var newField = document.getElementById('credentialsNew1');
            var confirmField = document.getElementById('credentialsNew2');

            document.getElementById('encryptedCredentials').value =
                await encryptText(publicKey, currentField.value);
            document.getElementById('encryptedCredentialsNew1').value =
                await encryptText(publicKey, newField.value);
            document.getElementById('encryptedCredentialsNew2').value =
                await encryptText(publicKey, confirmField.value);

            // nothing readable leaves the page
            currentField.value = '';
            newField.value = '';
            confirmField.value = '';
            form.submit();
        }

        document.addEventListener('DOMContentLoaded', function () {
            var form = document.getElementById('changePasswordForm');

            if (!form) {
                return;
            }

            form.addEventListener('submit', function (event) {
                if (form.dataset.encrypting === 'true') {
                    return;
                }

                event.preventDefault();
                form.dataset.encrypting = 'true';
                encryptAndSubmit(form).catch(function (error) {
                    form.dataset.encrypting = 'false';
                    if (window.console && window.console.error) {
                        window.console.error('Password change encryption failed before submit.', error);
                    }

                    if (error && error.message === 'CHANGE_ENCRYPTION_PUBLIC_KEY_MISSING') {
                        window.alert('\uc554\ud638 \ubcc0\uacbd \uc554\ud638\ud654 \ud0a4\ub97c \ubd88\ub7ec\uc624\uc9c0 \ubabb\ud588\uc2b5\ub2c8\ub2e4. \uad00\ub9ac\uc790\uc5d0\uac8c \ubb38\uc758\ud558\uc138\uc694.');
                    } else if (error && error.message === 'CHANGE_ENCRYPTION_WEBCRYPTO_UNAVAILABLE') {
                        window.alert('\ud604\uc7ac \ube0c\ub77c\uc6b0\uc800\uc5d0\uc11c \uc554\ud638\ud654\ub97c \uc9c0\uc6d0\ud558\uc9c0 \uc54a\uc2b5\ub2c8\ub2e4. \ucd5c\uc2e0 \ube0c\ub77c\uc6b0\uc800\ub97c \uc0ac\uc6a9\ud574 \uc8fc\uc138\uc694.');
                    } else {
                        window.alert('\uc554\ud638 \uc815\ubcf4 \uc554\ud638\ud654\uc5d0 \uc2e4\ud328\ud588\uc2b5\ub2c8\ub2e4. \uad00\ub9ac\uc790\uc5d0\uac8c \ubb38\uc758\ud558\uc138\uc694.');
                    }
                });
            });
        });
    }());
    //]]>
    </script>
</head>
<body class="ovirt-container">
    <c:if test="${ssoSession.clientId == null}">
        <c:redirect url="${ssoContext.engineUrl}" />
    </c:if>

    <c:choose>
        <c:when test="${ssoSession.status == 'authenticated'}">
            <c:set var="ssoUserName" value="${ssoSession.userId}" />
            <c:set var="ssoUserProfile" value="${ssoSession.profile}" />
        </c:when>
        <c:when test="${ssoSession.changePasswdCredentials != null && ssoSession.changePasswdCredentials.username != null }">
            <c:set var="ssoUserName" value="${ssoSession.changePasswdCredentials.username}" />
            <c:set var="ssoUserProfile" value="${ssoSession.changePasswdCredentials.profile}" />
        </c:when>
        <c:otherwise>
            <%-- Nothing says whose password this would change - the session carries no credentials
                 and nobody is logged in, which is what a bookmark of this page opened later looks
                 like. Rendering it anyway posted an empty user name, and the answer to that was an
                 error on this same page: a form that cannot be filled in and cannot be left.
                 Sending the user to log in is where they were going to have to start. --%>
            <c:redirect url="/login.html" />
        </c:otherwise>
    </c:choose>

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
                        <fmt:message key="changepasswordpage.usermessage" bundle="${changepasswordpage}" />
                        <b>${ssoUserName}@${ssoUserProfile}</b>
                    </h1>
                </header>

                <div class="pf-c-login__main-body">
                    <form
                        id="changePasswordForm"
                        novalidate class="pf-c-form"
                        method="post"
                        action="${pageContext.request.contextPath}/interactive-change-passwd"
                        enctype="application/x-www-form-urlencoded"
                    >
                        <p class="pf-c-form__helper-text pf-m-error">
                            <c:if test="${ssoSession.changePasswdMessage != null && ssoSession.changePasswdMessage != ''}">
                                <i class="fas fa-exclamation-circle pf-c-form__helper-text-icon"></i>
                                <c:out value="${ssoSession.changePasswdMessage}"/>
                                <c:set target="${ssoSession}" property="changePasswdMessage" value="" />
                            </c:if>
                        </p>

                        <input type="hidden" class="form-control" id="username" placeholder="username" name="username" value="${ssoUserName}">
                        <input type="hidden" class="form-control" id="profile" placeholder="profile" name="profile" value="${ssoUserProfile}">

                        <input type="hidden" id="changePublicKey" value="${fn:escapeXml(changeEncryptionPublicKey)}">
                        <input type="hidden" id="encryptedCredentials" name="encryptedCredentials">
                        <input type="hidden" id="encryptedCredentialsNew1" name="encryptedCredentialsNew1">
                        <input type="hidden" id="encryptedCredentialsNew2" name="encryptedCredentialsNew2">

                        <div class="pf-form__group">
                            <label class="pf-c-form__label-text" for="oldPassword">
                                <fmt:message key="changepasswordpage.oldpassword" bundle="${changepasswordpage}" />
                            </label>
                            <input type="password" id="credentials" name="credentials" class="pf-c-form-control" autofocus tabIndex="1">
                        </div>
                        <div class="pf-form__group">
                            <label class="pf-c-form__label-text" for="username">
                                <fmt:message key="changepasswordpage.newpassword" bundle="${changepasswordpage}" />
                            </label>
                            <input type="password" id="credentialsNew1" name="credentialsNew1" class="pf-c-form-control" tabIndex="2">
                        </div>
                        <div class="pf-form__group">
                            <label class="pf-c-form__label-text" for="username">
                                <fmt:message key="changepasswordpage.retypepassword" bundle="${changepasswordpage}" />
                            </label>
                            <input type="password" id="credentialsNew2" name="credentialsNew2" class="pf-c-form-control" tabIndex="3">
                        </div>

                        <div class="pf-c-form__group pf-m-action">
                            <button class="pf-c-button pf-m-primary pf-m-block" type="submit" tabIndex="4">
                                <fmt:message key="changepasswordpage.changepassword" bundle="${changepasswordpage}" />
                            </button>
                        </div>
                    </form>
                </div>
            </main>

            <footer class="pf-c-login__footer">
                <p class="obrand_loginPageSubtitle"></p>
            </footer>
        </div>
    </div>
</body>
</html>
