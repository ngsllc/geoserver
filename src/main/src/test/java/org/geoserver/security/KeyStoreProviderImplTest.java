/*
 * (c) 2024 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security;

import static org.junit.Assert.*;

import java.io.IOException;
import org.geoserver.test.GeoServerSystemTestSupport;
import org.junit.Test;

/** Test class for KeyStoreProviderImpl keystore type configuration functionality. */
public class KeyStoreProviderImplTest extends GeoServerSystemTestSupport {

    @Test
    public void testGetKeyStoreType() {
        // Test default keystore type
        String defaultType = KeyStoreProviderImpl.getKeyStoreType();
        assertEquals("Should default to JCEKS", "JCEKS", defaultType);
    }

    @Test
    public void testEnvironmentVariableOverride() {
        // Test that environment variable can override default keystore type
        String originalType = System.getenv("GEOSERVER_KEYSTORE_TYPE");

        try {
            // Set environment variable
            System.setProperty("GEOSERVER_KEYSTORE_TYPE", "BCFKS");
            String keystoreType = KeyStoreProviderImpl.getKeyStoreType();
            assertEquals("Should respect environment variable", "BCFKS", keystoreType);
        } finally {
            // Restore original value
            if (originalType != null) {
                System.setProperty("GEOSERVER_KEYSTORE_TYPE", originalType);
            } else {
                System.clearProperty("GEOSERVER_KEYSTORE_TYPE");
            }
        }
    }

    @Test
    public void testKeyStoreProviderCreation() throws IOException {
        // Test that KeyStoreProviderImpl can be created and initialized
        KeyStoreProviderImpl provider = new KeyStoreProviderImpl();
        assertNotNull("Provider should be created", provider);

        // Test file naming
        String defaultFileName = provider.getDefaultFileName();
        assertNotNull("Default file name should not be null", defaultFileName);
        assertTrue("Default file name should contain keystore type", defaultFileName.contains("geoserver."));

        String preparedFileName = provider.getPreparedFileName();
        assertNotNull("Prepared file name should not be null", preparedFileName);
        assertTrue("Prepared file name should contain .new suffix", preparedFileName.endsWith(".new"));
    }

    @Test
    public void testSupportedKeystoreTypes() {
        // Test that supported keystore types work
        String[] supportedTypes = {"JCEKS", "BCFKS", "PKCS12"};

        for (String keystoreType : supportedTypes) {
            try {
                System.setProperty("GEOSERVER_KEYSTORE_TYPE", keystoreType);
                String actualType = KeyStoreProviderImpl.getKeyStoreType();
                assertEquals("Should support " + keystoreType, keystoreType, actualType);
            } finally {
                System.clearProperty("GEOSERVER_KEYSTORE_TYPE");
            }
        }
    }

    @Test
    public void testConstants() {
        // Test that constants are properly defined
        assertEquals("JCEKS should be default", "JCEKS", KeyStoreProviderImpl.DEFAULT_KEYSTORE_TYPE);
        assertEquals(
                "Environment variable should be defined",
                "GEOSERVER_KEYSTORE_TYPE",
                KeyStoreProviderImpl.KEYSTORE_TYPE_ENV_VAR);
    }
}
