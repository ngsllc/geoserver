/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldif.LDIFReader;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.geotools.util.logging.Logging;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

/**
 * UnboundID In-Memory LDAP server for testing. Replaces ApacheDS to avoid BouncyCastle dependency conflicts.
 *
 * @author "Mauro Bartolomeoli - mauro.bartolomeoli@geo-solutions.it"
 * @author Niels Charlier
 */
public class UnboundIDLDAPTestServer {
    public static final int LDAP_SERVER_PORT = 10389;
    public static final String LDAP_SERVER_URL = "ldap://127.0.0.1:" + LDAP_SERVER_PORT;
    public static final String LDAP_BASE_PATH = "dc=example,dc=com";
    public static final String DEFAULT_PRINCIPAL = "uid=admin,ou=system";
    public static final String DEFAULT_PASSWORD = "secret";

    static final Logger LOGGER = Logging.getLogger(UnboundIDLDAPTestServer.class);

    private static InMemoryDirectoryServer server;

    /**
     * Start an embedded UnboundID LDAP server.
     *
     * @param port the port on which the server will be listening.
     * @param baseDN The base DN for the LDAP server.
     * @param ldifResource The LDIF file to load.
     * @throws LDAPException if server cannot be started
     */
    public static synchronized void startServer(int port, String baseDN, Resource ldifResource) throws Exception {
        if (server != null) {
            return; // Already started
        }

        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(baseDN);
            config.addAdditionalBindCredentials(DEFAULT_PRINCIPAL, DEFAULT_PASSWORD);
            config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("ldap", port));
            config.setSchema(null); // Use default schema
            config.setEnforceAttributeSyntaxCompliance(false);
            config.setEnforceSingleStructuralObjectClass(false);
            // Enable authentication with password attributes in LDIF
            config.setPasswordAttributes("userPassword");

            server = new InMemoryDirectoryServer(config);

            // Load LDIF data if provided
            if (ldifResource != null && ldifResource.exists()) {
                try (InputStream is = ldifResource.getInputStream()) {
                    server.importFromLDIF(true, new LDIFReader(is));
                }
            }

            server.startListening();
            LOGGER.info("UnboundID LDAP server started on port " + port);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to start UnboundID LDAP server", e);
            throw e;
        }
    }

    /** Start server with default settings. */
    public static void startServer() throws Exception {
        startServer(LDAP_SERVER_PORT, LDAP_BASE_PATH, new ClassPathResource("data.ldif"));
    }

    /** Shuts down the embedded server. */
    public static synchronized void shutdownServer() {
        if (server != null) {
            server.shutDown(true);
            server = null;
            LOGGER.info("UnboundID LDAP server shut down");
        }
    }

    /** Clear all data from the server. */
    public static void clearData(String baseDN) throws Exception {
        if (server != null) {
            server.clear();
            server.add("dn: " + baseDN, "objectClass: top", "objectClass: domain", "dc: example");
        }
    }

    /** Reload LDIF data. */
    public static void reloadData(Resource ldifResource) throws Exception {
        if (server != null && ldifResource != null && ldifResource.exists()) {
            server.clear();
            try (InputStream is = ldifResource.getInputStream();
                    LDIFReader reader = new LDIFReader(is)) {
                server.importFromLDIF(true, reader);
            }
        }
    }

    /** Get the server instance (for advanced operations). */
    public static InMemoryDirectoryServer getServer() {
        return server;
    }
}
