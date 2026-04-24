/* (c) 2025 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import org.geoserver.platform.resource.Resource;
import org.geoserver.security.password.GeoServerDigestPasswordEncoder;
import org.geoserver.security.password.GeoServerPBEPasswordEncoder;
import org.geoserver.security.password.GeoServerPasswordEncoder;
import org.geoserver.test.GeoServerSystemTestSupport;
import org.geotools.util.logging.Logging;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Integration tests for FIPS mode switching functionality.
 *
 * <p>These tests verify that GeoServer correctly handles switching between FIPS and non-FIPS modes, including:
 *
 * <ul>
 *   <li>Keystore type selection based on FIPS mode
 *   <li>Password encoder availability and behavior
 *   <li>Keystore migration when switching modes
 *   <li>Multiple round-trip mode switches
 *   <li>Secret key preservation across mode switches
 * </ul>
 */
public class FipsModeSwitchingIntegrationTest extends GeoServerSystemTestSupport {

    private static final Logger LOGGER = Logging.getLogger(FipsModeSwitchingIntegrationTest.class);

    private static final String TEST_SECRET_ALIAS = "integration-test-secret";
    private static final String TEST_SECRET_VALUE = "integration-test-value-12345";
    private static final String TEST_PASSWORD = "testPassword123!";

    private String originalFipsMode;

    @Before
    public void saveOriginalFipsMode() {
        originalFipsMode = System.getProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        LOGGER.log(Level.FINE, "Original FIPS mode setting: " + originalFipsMode);
        org.geoserver.data.test.SystemTestData.resetCachedKeystoreType();
    }

    @After
    public void restoreOriginalFipsMode() throws Exception {
        if (originalFipsMode != null) {
            System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, originalFipsMode);
        } else {
            System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        }
        org.geoserver.data.test.SystemTestData.resetCachedKeystoreType();
        getSecurityManager().getKeyStoreProvider().reloadKeyStore();
        LOGGER.log(Level.FINE, "Restored FIPS mode to: " + originalFipsMode);
    }

    /** Test that keystore type changes based on FIPS mode: BCFKS for FIPS, JCEKS for non-FIPS. */
    @Test
    public void testKeystoreTypeChangesWithFipsMode() throws Exception {
        LOGGER.fine("=== Test: Keystore type changes with FIPS mode ===");

        // Non-FIPS mode should use JCEKS
        setFipsMode(false);
        assertEquals("Non-FIPS mode should use JCEKS", "JCEKS", KeyStoreProviderImpl.getKeyStoreType());
        assertFalse("isFipsMode() should return false", KeyStoreProviderImpl.isFipsMode());

        // FIPS mode uses BCFKS
        setFipsMode(true);
        assertEquals("FIPS mode should use BCFKS", "BCFKS", KeyStoreProviderImpl.getKeyStoreType());
        assertTrue("isFipsMode() should return true", KeyStoreProviderImpl.isFipsMode());

        // Back to non-FIPS mode, should use JCEKS
        setFipsMode(false);
        assertEquals("Non-FIPS mode should use JCEKS", "JCEKS", KeyStoreProviderImpl.getKeyStoreType());
        assertFalse("isFipsMode() should return false", KeyStoreProviderImpl.isFipsMode());

        LOGGER.fine("Test passed: Keystore type changes with FIPS mode");
    }

    /** Test that secret keys are preserved when switching between FIPS and non-FIPS modes. */
    @Test
    public void testSecretKeyPreservationAcrossModeSwitch() throws Exception {
        LOGGER.fine("=== Test: Secret key preservation across mode switch ===");
        deleteKeystoreFiles();

        // Step 1: Start in non-FIPS mode and store a secret
        setFipsMode(false);
        KeyStoreProvider ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        ksp.setSecretKey(TEST_SECRET_ALIAS, TEST_SECRET_VALUE.toCharArray());
        ksp.storeKeyStore();
        assertTrue("Secret should exist after storing", ksp.containsAlias(TEST_SECRET_ALIAS));

        SecretKey originalKey = ksp.getSecretKey(TEST_SECRET_ALIAS);
        assertNotNull("Original key should not be null", originalKey);
        byte[] originalKeyBytes = originalKey.getEncoded();
        LOGGER.fine("Stored secret in JCEKS keystore");

        // Step 2: Switch to FIPS mode
        setFipsMode(true);
        ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        assertTrue("Secret should exist after FIPS switch", ksp.containsAlias(TEST_SECRET_ALIAS));
        SecretKey fipsKey = ksp.getSecretKey(TEST_SECRET_ALIAS);
        assertNotNull("FIPS key should not be null", fipsKey);
        assertArrayEquals("Key bytes should be preserved after FIPS switch", originalKeyBytes, fipsKey.getEncoded());
        LOGGER.fine("Secret preserved after switching to BCFKS");

        // Step 3: Switch back to non-FIPS mode
        setFipsMode(false);
        ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        assertTrue("Secret should exist after switching back", ksp.containsAlias(TEST_SECRET_ALIAS));
        SecretKey restoredKey = ksp.getSecretKey(TEST_SECRET_ALIAS);
        assertNotNull("Restored key should not be null", restoredKey);
        assertArrayEquals("Key bytes should be preserved after round-trip", originalKeyBytes, restoredKey.getEncoded());
        LOGGER.fine("Secret preserved after switching back to JCEKS");

        LOGGER.fine("Test passed: Secret keys preserved across mode switches");
    }

    /** Test that password encoders are correctly available based on FIPS mode. */
    @Test
    public void testPasswordEncoderAvailabilityInFipsMode() throws Exception {
        LOGGER.fine("=== Test: Password encoder availability in FIPS mode ===");

        // In non-FIPS mode, all encoders should be available
        setFipsMode(false);
        GeoServerSecurityManager manager = getSecurityManager();

        GeoServerPasswordEncoder digestEncoder = manager.loadPasswordEncoder(GeoServerDigestPasswordEncoder.class);
        assertNotNull("Digest encoder should be available in non-FIPS mode", digestEncoder);

        GeoServerPasswordEncoder strongPbeEncoder =
                manager.loadPasswordEncoder(GeoServerPBEPasswordEncoder.class, true, true);
        assertNotNull("Strong PBE encoder should be available in non-FIPS mode", strongPbeEncoder);

        // In FIPS mode, strong encoders should still work
        setFipsMode(true);
        manager = getSecurityManager();

        digestEncoder = manager.loadPasswordEncoder(GeoServerDigestPasswordEncoder.class);
        assertNotNull("Digest encoder should be available in FIPS mode", digestEncoder);

        // Test that digest encoder can encode/verify passwords
        String encoded = digestEncoder.encodePassword(TEST_PASSWORD, null);
        assertNotNull("Encoded password should not be null", encoded);
        assertTrue("Password should verify correctly", digestEncoder.isPasswordValid(encoded, TEST_PASSWORD, null));

        LOGGER.fine("Test passed: Password encoders work correctly in FIPS mode");
    }

    /** Test multiple rapid switches between FIPS and non-FIPS modes. */
    @Test
    public void testMultipleRapidModeSwitches() throws Exception {
        LOGGER.fine("=== Test: Multiple rapid mode switches ===");
        deleteKeystoreFiles();

        // Store a secret
        setFipsMode(false);
        KeyStoreProvider ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();
        ksp.setSecretKey(TEST_SECRET_ALIAS, TEST_SECRET_VALUE.toCharArray());
        ksp.storeKeyStore();

        // Perform multiple rapid switches
        for (int i = 0; i < 3; i++) {
            LOGGER.fine("Rapid switch iteration " + (i + 1));

            // Switch to FIPS
            setFipsMode(true);
            ksp = getSecurityManager().getKeyStoreProvider();
            ksp.reloadKeyStore();
            assertEquals("BCFKS", KeyStoreProviderImpl.getKeyStoreType());
            assertTrue("Secret should exist in FIPS mode", ksp.containsAlias(TEST_SECRET_ALIAS));

            // Switch to non-FIPS
            setFipsMode(false);
            ksp = getSecurityManager().getKeyStoreProvider();
            ksp.reloadKeyStore();
            assertEquals("JCEKS", KeyStoreProviderImpl.getKeyStoreType());
            assertTrue("Secret should exist in non-FIPS mode", ksp.containsAlias(TEST_SECRET_ALIAS));
        }

        LOGGER.fine("Test passed: Multiple rapid mode switches handled correctly");
    }

    /** Test that backup files are created during migration. */
    @Test
    public void testBackupFileCreationDuringMigration() throws Exception {
        LOGGER.fine("=== Test: Backup file creation during migration ===");
        deleteKeystoreFiles();

        // Create a keystore in non-FIPS mode
        setFipsMode(false);
        KeyStoreProvider ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();
        ksp.setSecretKey(TEST_SECRET_ALIAS, TEST_SECRET_VALUE.toCharArray());
        ksp.storeKeyStore();

        Resource securityDir = getSecurityManager().security();
        assertTrue("JCEKS file should exist", securityDir.get("geoserver.jceks").getType() == Resource.Type.RESOURCE);

        // Switch to FIPS mode (triggers migration)
        setFipsMode(true);
        ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        // After successful migration, BCFKS should exist
        assertTrue(
                "BCFKS file should exist after migration",
                securityDir.get("geoserver.bcfks").getType() == Resource.Type.RESOURCE);

        LOGGER.fine("Test passed: Migration creates proper keystore files");
    }

    /** Test system property takes precedence over environment variable. */
    @Test
    public void testSystemPropertyPrecedence() throws Exception {
        LOGGER.fine("=== Test: System property precedence ===");

        // Set system property to true
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");

        assertTrue("FIPS mode should be enabled via system property", KeyStoreProviderImpl.isFipsMode());
        assertEquals("BCFKS", KeyStoreProviderImpl.getKeyStoreType());

        // Set system property to false
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "false");

        assertFalse("FIPS mode should be disabled via system property", KeyStoreProviderImpl.isFipsMode());
        assertEquals("JCEKS", KeyStoreProviderImpl.getKeyStoreType());

        LOGGER.fine("Test passed: System property precedence works correctly");
    }

    // Helper methods

    private void setFipsMode(boolean enabled) {
        if (enabled) {
            System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");
        } else {
            System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "false");
        }
        org.geoserver.data.test.SystemTestData.resetCachedKeystoreType();
        LOGGER.fine("Set FIPS mode to: " + enabled);
    }

    private void deleteKeystoreFiles() throws Exception {
        Resource securityDir = getSecurityManager().security();

        deleteIfExists(securityDir.get("geoserver.jceks"));
        deleteIfExists(securityDir.get("geoserver.bcfks"));
        deleteIfExists(securityDir.get("geoserver.jceks.backup"));
        deleteIfExists(securityDir.get("geoserver.bcfks.backup"));

        LOGGER.fine("Cleaned up keystore files");
    }

    private void deleteIfExists(Resource resource) {
        if (resource.getType() == Resource.Type.RESOURCE) {
            resource.delete();
        }
    }
}
