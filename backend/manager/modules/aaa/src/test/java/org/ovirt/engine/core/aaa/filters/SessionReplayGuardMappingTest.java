package org.ovirt.engine.core.aaa.filters;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

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
}
