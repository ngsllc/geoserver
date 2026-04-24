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
import org.geoserver.test.GeoServerSystemTestSupport;
import org.geotools.util.logging.Logging;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests keystore migration between FIPS and non-FIPS modes.
 *
 * <p>This test verifies that keystores can be automatically migrated: - From JCEKS (non-FIPS) to BCFKS (FIPS) - From
 * BCFKS (FIPS) to JCEKS (non-FIPS) - Keys are preserved during migration - Multiple round-trip migrations work
 * correctly
 */
public class KeyStoreFipsMigrationTest extends GeoServerSystemTestSupport {

    private static final Logger LOGGER = Logging.getLogger(KeyStoreFipsMigrationTest.class);
    private static final String TEST_KEY_ALIAS = "test-migration-key";
    private static final String TEST_KEY_VALUE = "test-secret-value";

    private String originalFipsMode;

    @Before
    public void saveOriginalFipsMode() {
        originalFipsMode = System.getProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        LOGGER.log(Level.FINE, "Saved original FIPS mode: " + originalFipsMode);
        // Clear the static cache in SystemTestData to ensure tests see the correct keystore type
        org.geoserver.data.test.SystemTestData.resetCachedKeystoreType();
    }

    @After
    public void restoreOriginalFipsMode() throws Exception {
        if (originalFipsMode != null) {
            System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, originalFipsMode);
        } else {
            System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        }
        // Clear the static cache in SystemTestData to ensure next test sees the correct keystore type
        org.geoserver.data.test.SystemTestData.resetCachedKeystoreType();
        // Force reload to ensure clean state for next test
        getSecurityManager().getKeyStoreProvider().reloadKeyStore();
        LOGGER.log(Level.FINE, "Restored original FIPS mode: " + originalFipsMode);
    }

    @Test
    public void testMigrateFromNonFipsToFips() throws Exception {
        LOGGER.log(Level.FINE, "=== Test: Migrate from non-FIPS to FIPS ===");

        // Step 1: Start in non-FIPS mode and create a keystore with test data
        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        deleteKeystoreFiles();

        KeyStoreProvider ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        // Verify we're in non-FIPS mode by checking the expected keystore type
        assertEquals("JCEKS", KeyStoreProviderImpl.getKeyStoreType());
        LOGGER.log(Level.FINE, "Created JCEKS keystore");

        // Add test key
        ksp.setSecretKey(TEST_KEY_ALIAS, TEST_KEY_VALUE.toCharArray());
        ksp.storeKeyStore();

        // Verify key exists
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS));
        SecretKey originalKey = ksp.getSecretKey(TEST_KEY_ALIAS);
        assertNotNull(originalKey);
        LOGGER.log(Level.FINE, "Stored test key in JCEKS keystore"); // Verify file exists with .jceks extension
        Resource securityDir = getSecurityManager().security();
        assertTrue(securityDir.get("geoserver.jceks").getType() == Resource.Type.RESOURCE);

        // Step 2: Switch to FIPS mode and verify migration
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");

        // Reload triggers migration
        ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        // Verify we're in FIPS mode
        assertEquals("BCFKS", KeyStoreProviderImpl.getKeyStoreType());
        LOGGER.log(Level.FINE, "Migrated to BCFKS keystore");

        // Verify the key is still accessible
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS));
        SecretKey migratedKey = ksp.getSecretKey(TEST_KEY_ALIAS);
        assertNotNull(migratedKey);
        LOGGER.log(Level.FINE, "Successfully retrieved key from BCFKS keystore");

        // Verify file exists with .bcfks extension
        assertTrue(securityDir.get("geoserver.bcfks").getType() == Resource.Type.RESOURCE);
    }

    @Test
    public void testMigrateFromFipsToNonFips() throws Exception {
        LOGGER.log(Level.FINE, "=== Test: Migrate from FIPS to non-FIPS ===");

        // Step 1: Start in FIPS mode and create a keystore with test data
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");
        deleteKeystoreFiles();

        KeyStoreProvider ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        // Verify we're in FIPS mode
        assertEquals("BCFKS", KeyStoreProviderImpl.getKeyStoreType());
        LOGGER.log(Level.FINE, "Created BCFKS keystore");

        // Add test key
        ksp.setSecretKey(TEST_KEY_ALIAS, TEST_KEY_VALUE.toCharArray());
        ksp.storeKeyStore();

        // Verify key exists
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS));
        SecretKey originalKey = ksp.getSecretKey(TEST_KEY_ALIAS);
        assertNotNull(originalKey);
        LOGGER.log(Level.FINE, "Stored test key in BCFKS keystore"); // Verify file exists with .bcfks extension
        Resource securityDir = getSecurityManager().security();
        assertTrue(securityDir.get("geoserver.bcfks").getType() == Resource.Type.RESOURCE);

        // Step 2: Switch to non-FIPS mode and verify migration
        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);

        // Reload triggers migration
        ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        // Verify we're in non-FIPS mode
        assertEquals("JCEKS", KeyStoreProviderImpl.getKeyStoreType());
        LOGGER.log(Level.FINE, "Migrated to JCEKS keystore");

        // Verify the key is still accessible
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS));
        SecretKey migratedKey = ksp.getSecretKey(TEST_KEY_ALIAS);
        assertNotNull(migratedKey);
        LOGGER.log(Level.FINE, "Successfully retrieved key from JCEKS keystore");

        // Verify file exists with .jceks extension
        assertTrue(securityDir.get("geoserver.jceks").getType() == Resource.Type.RESOURCE);
    }

    @Test
    public void testRoundTripMigration() throws Exception {
        LOGGER.log(Level.FINE, "=== Test: Round-trip migration (non-FIPS -> FIPS -> non-FIPS) ===");

        // Start in non-FIPS mode
        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        deleteKeystoreFiles();

        KeyStoreProvider ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        // Add multiple test keys
        ksp.setSecretKey(TEST_KEY_ALIAS + "_1", "value1".toCharArray());
        ksp.setSecretKey(TEST_KEY_ALIAS + "_2", "value2".toCharArray());
        ksp.setSecretKey(TEST_KEY_ALIAS + "_3", "value3".toCharArray());
        ksp.storeKeyStore();
        LOGGER.log(Level.FINE, "Created JCEKS keystore with 3 test keys");

        // Save the encoded keys before migration
        byte[] key1Bytes = ksp.getSecretKey(TEST_KEY_ALIAS + "_1").getEncoded();
        byte[] key2Bytes = ksp.getSecretKey(TEST_KEY_ALIAS + "_2").getEncoded();
        byte[] key3Bytes = ksp.getSecretKey(TEST_KEY_ALIAS + "_3").getEncoded();

        // Migrate to FIPS
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");
        ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        assertEquals("BCFKS", KeyStoreProviderImpl.getKeyStoreType());
        assertArrayEquals(key1Bytes, ksp.getSecretKey(TEST_KEY_ALIAS + "_1").getEncoded());
        assertArrayEquals(key2Bytes, ksp.getSecretKey(TEST_KEY_ALIAS + "_2").getEncoded());
        assertArrayEquals(key3Bytes, ksp.getSecretKey(TEST_KEY_ALIAS + "_3").getEncoded());
        LOGGER.log(Level.FINE, "Migrated to BCFKS, all keys preserved");

        // Migrate back to non-FIPS
        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        assertEquals("JCEKS", KeyStoreProviderImpl.getKeyStoreType());
        assertArrayEquals(key1Bytes, ksp.getSecretKey(TEST_KEY_ALIAS + "_1").getEncoded());
        assertArrayEquals(key2Bytes, ksp.getSecretKey(TEST_KEY_ALIAS + "_2").getEncoded());
        assertArrayEquals(key3Bytes, ksp.getSecretKey(TEST_KEY_ALIAS + "_3").getEncoded());
        LOGGER.log(Level.FINE, "Migrated back to JCEKS, all keys preserved");

        // Add a new key after round-trip
        ksp.setSecretKey(TEST_KEY_ALIAS + "_4", "value4".toCharArray());
        ksp.storeKeyStore();

        // Just verify the new key exists and can be retrieved
        assertNotNull(ksp.getSecretKey(TEST_KEY_ALIAS + "_4"));
        assertNotNull(ksp.getSecretKey(TEST_KEY_ALIAS + "_4").getEncoded());
        LOGGER.log(Level.FINE, "Successfully added new key after round-trip migration");
    }

    @Test
    public void testMultipleRoundTrips() throws Exception {
        LOGGER.log(Level.FINE, "=== Test: Multiple round-trip migrations ===");

        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        deleteKeystoreFiles();

        KeyStoreProvider ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        // Add initial key
        ksp.setSecretKey(TEST_KEY_ALIAS, TEST_KEY_VALUE.toCharArray());
        ksp.storeKeyStore();

        // Save the encoded key bytes
        byte[] keyBytes = ksp.getSecretKey(TEST_KEY_ALIAS).getEncoded();

        // Perform 3 round trips
        for (int i = 1; i <= 3; i++) {
            LOGGER.log(Level.FINE, "Round trip #" + i);

            // To FIPS
            System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");
            ksp = getSecurityManager().getKeyStoreProvider();
            ksp.reloadKeyStore();
            assertEquals("BCFKS", KeyStoreProviderImpl.getKeyStoreType());
            assertArrayEquals(keyBytes, ksp.getSecretKey(TEST_KEY_ALIAS).getEncoded());

            // Back to non-FIPS
            System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
            ksp = getSecurityManager().getKeyStoreProvider();
            ksp.reloadKeyStore();
            assertEquals("JCEKS", KeyStoreProviderImpl.getKeyStoreType());
            assertArrayEquals(keyBytes, ksp.getSecretKey(TEST_KEY_ALIAS).getEncoded());
        }

        LOGGER.log(Level.FINE, "Successfully completed 3 round-trip migrations");
    }

    @Test
    public void testMigrationPreservesAllStandardKeys() throws Exception {
        LOGGER.log(Level.FINE, "=== Test: Migration preserves all standard GeoServer keys ===");

        // Start in non-FIPS mode
        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        deleteKeystoreFiles();

        KeyStoreProvider ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        // Ensure standard keys exist
        if (!ksp.hasConfigPasswordKey()) {
            ksp.setSecretKey(KeyStoreProviderImpl.CONFIGPASSWORDKEY, "config-password".toCharArray());
        }

        if (!ksp.hasUserGroupKey("default")) {
            ksp.setUserGroupKey("default", "default-ug-key".toCharArray());
        }

        ksp.storeKeyStore();

        // Verify keys exist
        assertTrue(ksp.hasConfigPasswordKey());
        assertTrue(ksp.hasUserGroupKey("default"));
        byte[] configKey = ksp.getConfigPasswordKey();
        byte[] ugKey = ksp.getUserGroupKey("default");
        LOGGER.log(Level.FINE, "Created standard keys in JCEKS keystore");

        // Migrate to FIPS
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");
        ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        // Verify keys still exist after migration
        assertTrue(ksp.hasConfigPasswordKey());
        assertTrue(ksp.hasUserGroupKey("default"));
        assertEquals(new String(configKey), new String(ksp.getConfigPasswordKey()));
        assertEquals(new String(ugKey), new String(ksp.getUserGroupKey("default")));
        LOGGER.log(Level.FINE, "All standard keys preserved after migration to BCFKS");
    }

    @Test
    public void testFipsModeDetection() {
        LOGGER.log(Level.FINE, "=== Test: FIPS mode detection ===");

        // Test with no FIPS mode set
        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        assertFalse(KeyStoreProviderImpl.isFipsMode());
        assertEquals("JCEKS", KeyStoreProviderImpl.getKeyStoreType());

        // Test with FIPS mode enabled
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");
        assertTrue(KeyStoreProviderImpl.isFipsMode());
        assertEquals("BCFKS", KeyStoreProviderImpl.getKeyStoreType());

        // Test with FIPS mode disabled explicitly
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "false");
        assertFalse(KeyStoreProviderImpl.isFipsMode());
        assertEquals("JCEKS", KeyStoreProviderImpl.getKeyStoreType());

        // Test case insensitivity
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "TRUE");
        assertTrue(KeyStoreProviderImpl.isFipsMode());

        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "True");
        assertTrue(KeyStoreProviderImpl.isFipsMode());

        LOGGER.log(Level.FINE, "FIPS mode detection working correctly");
    }

    @Test
    public void testNoFileToNonFipsToFipsToNonFips() throws Exception {
        LOGGER.log(Level.FINE, "=== Test: No file -> non-FIPS -> FIPS -> non-FIPS ===");

        // Step 1: Start with no file, in non-FIPS mode
        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        deleteKeystoreFiles();

        KeyStoreProvider ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        // Should create JCEKS keystore
        assertEquals("JCEKS", KeyStoreProviderImpl.getKeyStoreType());
        Resource securityDir = getSecurityManager().security();
        assertTrue(securityDir.get("geoserver.jceks").getType() == Resource.Type.RESOURCE);
        LOGGER.log(Level.FINE, "Step 1: Created JCEKS keystore from scratch");

        // Add test keys
        ksp.setSecretKey(TEST_KEY_ALIAS + "_1", "value1".toCharArray());
        ksp.setSecretKey(TEST_KEY_ALIAS + "_2", "value2".toCharArray());
        ksp.storeKeyStore();
        LOGGER.log(Level.FINE, "Step 1: Added test keys to JCEKS");

        // Step 2: Switch to FIPS mode - should migrate JCEKS -> BCFKS
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");
        ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        assertEquals("BCFKS", KeyStoreProviderImpl.getKeyStoreType());

        // Debug: List all files in security directory
        LOGGER.log(Level.FINE, "Files in security directory:");
        for (Resource r : securityDir.list()) {
            LOGGER.log(Level.FINE, "  - " + r.name() + " (type: " + r.getType() + ")");
        }

        assertTrue(
                "geoserver.bcfks file should exist",
                securityDir.get("geoserver.bcfks").getType() == Resource.Type.RESOURCE);
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS + "_1"));
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS + "_2"));
        assertNotNull(ksp.getSecretKey(TEST_KEY_ALIAS + "_1"));
        assertNotNull(ksp.getSecretKey(TEST_KEY_ALIAS + "_2"));
        LOGGER.log(Level.FINE, "Step 2: Migrated to BCFKS, keys preserved");

        // Add another key in FIPS mode
        ksp.setSecretKey(TEST_KEY_ALIAS + "_3", "value3".toCharArray());
        ksp.storeKeyStore();
        LOGGER.log(Level.FINE, "Step 2: Added additional key in BCFKS");

        // Step 3: Switch back to non-FIPS mode - should migrate BCFKS -> JCEKS
        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        assertEquals("JCEKS", KeyStoreProviderImpl.getKeyStoreType());
        assertTrue(
                "geoserver.jceks file should exist but does not. Files: "
                        + java.util.Arrays.toString(
                                securityDir.list().stream().map(r -> r.name()).toArray()),
                securityDir.get("geoserver.jceks").getType() == Resource.Type.RESOURCE);
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS + "_1"));
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS + "_2"));
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS + "_3"));
        assertNotNull(ksp.getSecretKey(TEST_KEY_ALIAS + "_1"));
        assertNotNull(ksp.getSecretKey(TEST_KEY_ALIAS + "_2"));
        assertNotNull(ksp.getSecretKey(TEST_KEY_ALIAS + "_3"));
        LOGGER.log(Level.FINE, "Step 3: Migrated back to JCEKS, all keys preserved");

        LOGGER.log(Level.FINE, "=== Test completed successfully ===");
    }

    @Test
    public void testNoFileToFipsToNonFipsToFips() throws Exception {
        LOGGER.log(Level.FINE, "=== Test: No file -> FIPS -> non-FIPS -> FIPS ===");

        // Step 1: Start with no file, in FIPS mode
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");
        deleteKeystoreFiles();

        KeyStoreProvider ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        // Should create BCFKS keystore
        assertEquals("BCFKS", KeyStoreProviderImpl.getKeyStoreType());
        Resource securityDir = getSecurityManager().security();
        assertTrue(securityDir.get("geoserver.bcfks").getType() == Resource.Type.RESOURCE);
        LOGGER.log(Level.FINE, "Step 1: Created BCFKS keystore from scratch");

        // Add test keys
        ksp.setSecretKey(TEST_KEY_ALIAS + "_1", "value1".toCharArray());
        ksp.setSecretKey(TEST_KEY_ALIAS + "_2", "value2".toCharArray());
        ksp.storeKeyStore();
        LOGGER.log(Level.FINE, "Step 1: Added test keys to BCFKS");

        // Step 2: Switch to non-FIPS mode - should migrate BCFKS -> JCEKS
        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        assertEquals("JCEKS", KeyStoreProviderImpl.getKeyStoreType());
        assertTrue(securityDir.get("geoserver.jceks").getType() == Resource.Type.RESOURCE);
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS + "_1"));
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS + "_2"));
        assertNotNull(ksp.getSecretKey(TEST_KEY_ALIAS + "_1"));
        assertNotNull(ksp.getSecretKey(TEST_KEY_ALIAS + "_2"));
        LOGGER.log(Level.FINE, "Step 2: Migrated to JCEKS, keys preserved");

        // Add another key in non-FIPS mode
        ksp.setSecretKey(TEST_KEY_ALIAS + "_3", "value3".toCharArray());
        ksp.storeKeyStore();
        LOGGER.log(Level.FINE, "Step 2: Added additional key in JCEKS");

        // Step 3: Switch back to FIPS mode - should migrate JCEKS -> BCFKS
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");
        ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        assertEquals("BCFKS", KeyStoreProviderImpl.getKeyStoreType());
        assertTrue(
                "geoserver.bcfks file should exist but does not. Files: "
                        + java.util.Arrays.toString(
                                securityDir.list().stream().map(r -> r.name()).toArray()),
                securityDir.get("geoserver.bcfks").getType() == Resource.Type.RESOURCE);
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS + "_1"));
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS + "_2"));
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS + "_3"));
        assertNotNull(ksp.getSecretKey(TEST_KEY_ALIAS + "_1"));
        assertNotNull(ksp.getSecretKey(TEST_KEY_ALIAS + "_2"));
        assertNotNull(ksp.getSecretKey(TEST_KEY_ALIAS + "_3"));
        LOGGER.log(Level.FINE, "Step 3: Migrated back to BCFKS, all keys preserved");

        LOGGER.log(Level.FINE, "=== Test completed successfully ===");
    }

    @Test
    public void testBackupCreatedDuringMigration() throws Exception {
        LOGGER.log(Level.FINE, "=== Test: Backup created during migration ===");

        // Step 1: Create a JCEKS keystore
        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        deleteKeystoreFiles();

        KeyStoreProvider ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();
        ksp.setSecretKey(TEST_KEY_ALIAS, TEST_KEY_VALUE.toCharArray());
        ksp.storeKeyStore();

        Resource securityDir = getSecurityManager().security();
        Resource jceksFile = securityDir.get("geoserver.jceks");
        assertTrue("JCEKS file should exist", jceksFile.getType() == Resource.Type.RESOURCE);

        // Record the original file size
        long originalSize = jceksFile.file().length();
        LOGGER.log(Level.FINE, "Original JCEKS file size: " + originalSize);

        // Step 2: Switch to FIPS mode - should create backup during migration
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");
        ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        // Verify migration succeeded
        assertEquals("BCFKS", KeyStoreProviderImpl.getKeyStoreType());
        Resource bcfksFile = securityDir.get("geoserver.bcfks");
        assertTrue("BCFKS file should exist", bcfksFile.getType() == Resource.Type.RESOURCE);

        // Verify backup is preserved after successful migration (for manual recovery)
        Resource backupFile = securityDir.get("geoserver.jceks.backup");
        assertTrue(
                "Backup should be preserved after migration for recovery purposes",
                backupFile.getType() == Resource.Type.RESOURCE);

        // Verify key was preserved
        assertTrue(ksp.containsAlias(TEST_KEY_ALIAS));
        assertNotNull(ksp.getSecretKey(TEST_KEY_ALIAS));

        LOGGER.log(Level.FINE, "=== Test completed: Backup mechanism verified ===");
    }

    @Test
    public void testConcurrentReloadKeyStore() throws Exception {
        LOGGER.log(Level.FINE, "=== Test: Concurrent reloadKeyStore calls ===");

        // Create initial keystore
        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        deleteKeystoreFiles();

        KeyStoreProvider ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();
        ksp.setSecretKey(TEST_KEY_ALIAS, TEST_KEY_VALUE.toCharArray());
        ksp.storeKeyStore();

        // Test concurrent reloads - should not cause race conditions
        final int threadCount = 5;
        final java.util.concurrent.CountDownLatch startLatch = new java.util.concurrent.CountDownLatch(1);
        final java.util.concurrent.CountDownLatch doneLatch = new java.util.concurrent.CountDownLatch(threadCount);
        final java.util.concurrent.atomic.AtomicInteger successCount = new java.util.concurrent.atomic.AtomicInteger(0);
        final java.util.concurrent.atomic.AtomicInteger failureCount = new java.util.concurrent.atomic.AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            final int threadNum = i;
            new Thread(() -> {
                        try {
                            startLatch.await(); // Wait for all threads to be ready
                            KeyStoreProvider threadKsp = getSecurityManager().getKeyStoreProvider();
                            threadKsp.reloadKeyStore();

                            // Verify keystore is functional after reload
                            if (threadKsp.containsAlias(TEST_KEY_ALIAS)) {
                                successCount.incrementAndGet();
                                LOGGER.log(Level.FINE, "Thread " + threadNum + " successfully reloaded");
                            } else {
                                failureCount.incrementAndGet();
                                LOGGER.log(Level.WARNING, "Thread " + threadNum + " reload failed");
                            }
                        } catch (Exception e) {
                            failureCount.incrementAndGet();
                            LOGGER.log(Level.SEVERE, "Thread " + threadNum + " threw exception", e);
                        } finally {
                            doneLatch.countDown();
                        }
                    })
                    .start();
        }

        // Start all threads simultaneously
        startLatch.countDown();

        // Wait for all threads to complete (with timeout)
        boolean completed = doneLatch.await(30, java.util.concurrent.TimeUnit.SECONDS);
        assertTrue("All threads should complete within timeout", completed);

        // Verify all threads succeeded
        assertEquals("All threads should succeed", threadCount, successCount.get());
        assertEquals("No threads should fail", 0, failureCount.get());

        LOGGER.log(Level.FINE, "=== Test completed: " + successCount.get() + " concurrent reloads succeeded ===");
    }

    @Test
    public void testConcurrentStoreKeyStore() throws Exception {
        LOGGER.log(Level.FINE, "=== Test: Concurrent storeKeyStore calls ===");

        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        deleteKeystoreFiles();

        KeyStoreProvider ksp = getSecurityManager().getKeyStoreProvider();
        ksp.reloadKeyStore();

        // Test concurrent stores - should not cause corruption
        final int threadCount = 5;
        final java.util.concurrent.CountDownLatch startLatch = new java.util.concurrent.CountDownLatch(1);
        final java.util.concurrent.CountDownLatch doneLatch = new java.util.concurrent.CountDownLatch(threadCount);
        final java.util.concurrent.atomic.AtomicInteger successCount = new java.util.concurrent.atomic.AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            final int threadNum = i;
            new Thread(() -> {
                        try {
                            startLatch.await();
                            KeyStoreProvider threadKsp = getSecurityManager().getKeyStoreProvider();
                            threadKsp.setSecretKey("thread_key_" + threadNum, ("value_" + threadNum).toCharArray());
                            threadKsp.storeKeyStore();
                            successCount.incrementAndGet();
                            LOGGER.log(Level.FINE, "Thread " + threadNum + " stored successfully");
                        } catch (Exception e) {
                            LOGGER.log(Level.SEVERE, "Thread " + threadNum + " failed", e);
                        } finally {
                            doneLatch.countDown();
                        }
                    })
                    .start();
        }

        startLatch.countDown();
        boolean completed = doneLatch.await(30, java.util.concurrent.TimeUnit.SECONDS);
        assertTrue("All threads should complete", completed);
        assertEquals("All stores should succeed", threadCount, successCount.get());

        // Verify all keys are present (reload to ensure consistency)
        ksp.reloadKeyStore();
        for (int i = 0; i < threadCount; i++) {
            assertTrue("Key from thread " + i + " should exist", ksp.containsAlias("thread_key_" + i));
        }

        LOGGER.log(Level.FINE, "=== Test completed: All keys stored successfully ===");
    }

    /** Helper method to delete all keystore files to ensure clean test state */
    private void deleteKeystoreFiles() throws Exception {
        Resource securityDir = getSecurityManager().security();

        // Delete all possible keystore files
        String[] extensions = {"jceks", "jks", "bcfks"};
        for (String ext : extensions) {
            Resource ksFile = securityDir.get("geoserver." + ext);
            if (ksFile.getType() == Resource.Type.RESOURCE) {
                ksFile.delete();
                LOGGER.log(Level.FINE, "Deleted keystore file: geoserver." + ext);
            }
        }

        // Also check for .new files
        for (String ext : extensions) {
            Resource ksFile = securityDir.get("geoserver." + ext + ".new");
            if (ksFile.getType() == Resource.Type.RESOURCE) {
                ksFile.delete();
                LOGGER.log(Level.FINE, "Deleted temporary keystore file: geoserver." + ext + ".new");
            }
        }

        // Delete backup files
        for (String ext : extensions) {
            Resource backupFile = securityDir.get("geoserver." + ext + ".backup");
            if (backupFile.getType() == Resource.Type.RESOURCE) {
                backupFile.delete();
                LOGGER.log(Level.FINE, "Deleted backup file: geoserver." + ext + ".backup");
            }
        }
    }
}
