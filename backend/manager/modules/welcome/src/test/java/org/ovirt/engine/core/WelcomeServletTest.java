package org.ovirt.engine.core;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.ovirt.engine.core.branding.BrandingManager;
import org.ovirt.engine.core.common.interfaces.BackendLocal;
import org.ovirt.engine.core.common.queries.QueryReturnValue;
import org.ovirt.engine.core.common.queries.QueryType;
import org.ovirt.engine.core.utils.MockConfigExtension;
import org.ovirt.engine.core.utils.servlet.LocaleFilter;

@ExtendWith({MockitoExtension.class, MockConfigExtension.class})
@MockitoSettings(strictness = Strictness.LENIENT)
public class WelcomeServletTest {
    @Spy
    WelcomeServlet testServlet;

    @Mock
    HttpServletRequest mockRequest;

    @Mock
    HttpSession mockSession;

    @Mock
    ServletContext mockContext;

    @Mock
    HttpServletResponse mockResponse;

    @Mock
    RequestDispatcher mockDispatcher;

    @Mock
    BackendLocal mockBackend;

    @Mock
    BrandingManager mockBrandingManager;

    final List<String> localeKeys = createLocaleKeys();

    private void mockBackendQuery(QueryType queryType, Object returnValue) {
        QueryReturnValue queryReturnValue = new QueryReturnValue();
        queryReturnValue.setReturnValue(returnValue);
        when(mockBackend.runPublicQuery(eq(queryType), any())).thenReturn(queryReturnValue);
    }

    @BeforeEach
    public void setUp() throws Exception {
        doReturn("http://localhost:8080/ovirt-engine/sso/credentials-change.html").when(testServlet).getCredentialsChangeUrl(any());
        testServlet.setBackend(mockBackend);
        testServlet.init(mockBrandingManager, "/ovirt-engine");
        mockBackendQuery(QueryType.GetConfigurationValue, "oVirtVersion");
        when(mockBrandingManager.getWelcomeSections(any())).thenReturn("Welcome Section HTML");
        // From the engine host itself, which needs no terminal serial.
        when(mockRequest.getRemoteAddr()).thenReturn("127.0.0.1");
    }

    @Test
    public void anUnregisteredTerminalSeesTheWebServersForbiddenPage() throws IOException, ServletException {
        when(mockRequest.getRemoteAddr()).thenReturn("192.0.2.10");
        when(mockRequest.getRequestURI()).thenReturn("/ovirt-engine/");
        when(mockResponse.getOutputStream()).thenReturn(mock(ServletOutputStream.class));
        testServlet.doGet(mockRequest, mockResponse);
        verify(mockResponse).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verify(mockResponse).setContentType("text/html; charset=iso-8859-1");
        verify(mockResponse, never()).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid client serial.");
        verify(mockRequest, never()).getSession(true);
    }

    @Test
    public void testDoGetHttpServletRequestHttpServletResponseNoDispatcher() throws IOException, ServletException {
        when(mockRequest.getAttribute(LocaleFilter.LOCALE)).thenReturn(Locale.JAPANESE);
        when(mockRequest.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/ovirt-engine/"));
        when(mockRequest.getServletContext()).thenReturn(mockContext);
        when(mockRequest.getSession(true)).thenReturn(mockSession);
        when(mockSession.getAttribute("authCode")).thenReturn("aU1KZG1OUytQSktnd29SQ3NIOVhWckls");
        when(mockSession.getAttribute("token")).thenReturn("aU1KZG1OUytQSktnd29SQ3NIOVhWckls");
        when(mockSession.getAttribute("error")).thenReturn("");
        when(mockSession.getAttribute("error_description")).thenReturn("");
        when(mockRequest.getServletContext().getAttribute("sso_logout_url")).thenReturn(
                new StringBuffer("http://localhost:8080/ovirt-engine/logout"));
        when(mockRequest.getServletContext().getAttribute("sso_switch_user_url")).thenReturn(
                new StringBuffer("http://localhost:8080/ovirt-engine/login"));
        testServlet.doGet(mockRequest, mockResponse);
        verify(mockRequest).setAttribute("localeKeys", localeKeys);
        //Make sure the content type contains UTF-8 so the characters display properly.
        verify(mockResponse).setContentType("text/html;charset=UTF-8");
    }

    @Test
    public void testDoGetHttpServletRequestHttpServletResponseWithDispatcher() throws IOException, ServletException {
        when(mockRequest.getAttribute(LocaleFilter.LOCALE)).thenReturn(Locale.JAPANESE);
        when(mockRequest.getRequestDispatcher("/WEB-INF/ovirt-engine.jsp")).thenReturn(mockDispatcher);
        when(mockRequest.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/ovirt-engine/"));
        when(mockRequest.getServletContext()).thenReturn(mockContext);
        when(mockRequest.getSession(true)).thenReturn(mockSession);
        when(mockSession.getAttribute("authCode")).thenReturn("aU1KZG1OUytQSktnd29SQ3NIOVhWckls");
        when(mockSession.getAttribute("token")).thenReturn("aU1KZG1OUytQSktnd29SQ3NIOVhWckls");
        when(mockSession.getAttribute("error")).thenReturn("");
        when(mockSession.getAttribute("error_description")).thenReturn("");
        when(mockRequest.getServletContext().getAttribute("sso_logout_url")).thenReturn(
                new StringBuffer("http://localhost:8080/ovirt-engine/logout"));
        when(mockRequest.getServletContext().getAttribute("sso_switch_user_url")).thenReturn(
                new StringBuffer("http://localhost:8080/ovirt-engine/login"));
        testServlet.doGet(mockRequest, mockResponse);
        verify(mockRequest).setAttribute("localeKeys", localeKeys);
        //Make sure the content type contains UTF-8 so the characters display properly.
        verify(mockResponse).setContentType("text/html;charset=UTF-8");
        //Make sure the include is called on the dispatcher.
        verify(mockDispatcher).include(mockRequest, mockResponse);
    }

    private List<String> createLocaleKeys() {
        // The product ships one language (languages.properties).
        List<String> keys = new ArrayList<>();
        keys.add("ko_KR");
        return keys;
    }
}
