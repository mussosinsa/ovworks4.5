package org.ovirt.engine.core.aaa.filters;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * Every way into the engine is judged the same way.
 *
 * <p>The guard began on the REST API alone. A copy of a browser's traffic is the same copy, and
 * was being answered "not authenticated" and left out of the audit log entirely - so the question
 * this asks is not whether the filter works but whether each application is asking it. A webapp
 * added later with no mapping would lose the refusal and the record together, and silently.</p>
 *
 * <p>Read from the deployment descriptors rather than from anything the filter itself says,
 * because what is deployed is what decides this.</p>
 */
public class SessionReplayGuardMappingTest {

    private static final String FILTER = "SessionReplayGuardFilter"; //$NON-NLS-1$

    /** Where each application's descriptor is, relative to this module. */
    private static final String[] DESCRIPTORS = {
            "../restapi/webapp/src/main/webapp/WEB-INF/web.xml", //$NON-NLS-1$
            "../services/src/main/webapp/WEB-INF/web.xml", //$NON-NLS-1$
            "../../../../frontend/webadmin/modules/webadmin/src/main/webapp/WEB-INF/web.xml", //$NON-NLS-1$
    };

    /** The filters that authenticate, which is what the guard has to come before. */
    private static final String[] AUTHENTICATING = {
            "SsoLoginFilter", "SsoRestApiAuthFilter", "EnforceAuthFilter", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    };

    @Test
    public void everyApplicationAsksTheGuard() throws IOException {
        for (String descriptor : DESCRIPTORS) {
            Path path = Path.of(descriptor);
            if (!Files.exists(path)) {
                // Run from somewhere this module cannot see the others from; nothing to say.
                continue;
            }
            String web = Files.readString(path);
            assertTrue(web.contains(FILTER), descriptor + " does not ask the guard"); //$NON-NLS-1$
        }
    }

    @Test
    public void theGuardIsAskedBeforeAnythingAuthenticates() throws IOException {
        // Afterwards, a copy carrying credentials of its own would already have been let in and
        // given a session, and the refusal would be about a session it no longer needed.
        for (String descriptor : DESCRIPTORS) {
            Path path = Path.of(descriptor);
            if (!Files.exists(path)) {
                continue;
            }
            String web = Files.readString(path);
            int guard = web.indexOf("<filter-name>" + FILTER + "</filter-name>"); //$NON-NLS-1$ //$NON-NLS-2$
            if (guard < 0) {
                continue;
            }
            for (String authenticating : AUTHENTICATING) {
                int at = web.indexOf("<filter-name>" + authenticating + "</filter-name>"); //$NON-NLS-1$ //$NON-NLS-2$
                assertTrue(at < 0 || guard < at,
                        descriptor + " asks the guard after " + authenticating); //$NON-NLS-1$
            }
        }
    }
    /**
     * Every servlet that signs somebody in or out is exempt from the guard.
     *
     * <p>Read from the descriptors rather than listed here, because an application that mounts one
     * of these at a path the filter does not know refuses the request that would sign somebody back
     * in - and the symptom is not a refusal anybody sees, it is the administration application
     * failing to start up with a null result from a query it made while loading.</p>
     */
    @Test
    public void theRequestsThatSignSomebodyInOrOutAreNotJudged() throws IOException {
        for (String descriptor : DESCRIPTORS) {
            Path path = Path.of(descriptor);
            if (!Files.exists(path)) {
                continue;
            }
            String web = Files.readString(path);
            for (String name : signingInOrOutServletsOf(web)) {
                for (String pattern : patternsOf(web, name)) {
                    assertTrue(SessionReplayGuardFilter.isSigningInOrOut(pattern),
                            descriptor + " maps " + name + " at " + pattern //$NON-NLS-1$ //$NON-NLS-2$
                                    + ", which the guard does not know to leave alone"); //$NON-NLS-1$
                }
            }
        }
    }

    /** The servlet-names of the servlets whose class signs somebody in or out. */
    private static List<String> signingInOrOutServletsOf(String web) {
        List<String> names = new ArrayList<>();
        Matcher servlet = Pattern.compile(
                "<servlet>(.*?)</servlet>", Pattern.DOTALL).matcher(web); //$NON-NLS-1$
        while (servlet.find()) {
            String declaration = servlet.group(1);
            String className = between(declaration, "servlet-class"); //$NON-NLS-1$
            if (className != null && SIGNS_IN_OR_OUT.matcher(className).find()) {
                names.add(between(declaration, "servlet-name")); //$NON-NLS-1$
            }
        }
        return names;
    }

    private static List<String> patternsOf(String web, String servletName) {
        List<String> patterns = new ArrayList<>();
        Matcher mapping = Pattern.compile(
                "<servlet-mapping>(.*?)</servlet-mapping>", Pattern.DOTALL).matcher(web); //$NON-NLS-1$
        while (mapping.find()) {
            String declaration = mapping.group(1);
            if (servletName.equals(between(declaration, "servlet-name"))) { //$NON-NLS-1$
                Matcher pattern = Pattern.compile(
                        "<url-pattern>\\s*(.*?)\\s*</url-pattern>").matcher(declaration); //$NON-NLS-1$
                while (pattern.find()) {
                    patterns.add(pattern.group(1));
                }
            }
        }
        return patterns;
    }

    private static String between(String xml, String element) {
        Matcher found = Pattern.compile(
                "<" + element + ">\\s*(.*?)\\s*</" + element + ">", Pattern.DOTALL).matcher(xml); //$NON-NLS-1$ //$NON-NLS-2$
        return found.find() ? found.group(1) : null;
    }

    /**
     * What such a servlet is called. Login, logout and the callback the identity provider returns
     * to; not SsoRestApiAuthFilter and the like, which authenticate a request rather than start a
     * session.
     */
    private static final Pattern SIGNS_IN_OR_OUT = Pattern.compile(
            "Sso(Login|Logout|PostLogin|Callback)Servlet$"); //$NON-NLS-1$
}
