/*
 * Copyright (c) 2024 Open Source Geospatial Foundation (OSGeo)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.geoserver.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.util.Enumeration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class MigrateKeystoreTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private File jceksKeystore;
    private File bcfksKeystore;
    private File pkcs12Keystore;
    private static final String PASSWORD = "testpassword";

    @Before
    public void setUp() throws Exception {
        // Add BouncyCastle provider for BCFKS support
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Create test keystores
        jceksKeystore = tempFolder.newFile("test.jceks");
        bcfksKeystore = tempFolder.newFile("test.bcfks");
        pkcs12Keystore = tempFolder.newFile("test.p12");

        // Create a JCEKS keystore with test data
        createTestJceksKeystore();
    }

    private void createTestJceksKeystore() throws Exception {
        KeyStore ks = KeyStore.getInstance("JCEKS");
        ks.load(null, PASSWORD.toCharArray());

        // Add a test secret key entry
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
        kg.init(128);
        javax.crypto.SecretKey secretKey = kg.generateKey();
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        ks.setEntry("test-secret", secretKeyEntry, new KeyStore.PasswordProtection(PASSWORD.toCharArray()));

        // Save the keystore
        try (FileOutputStream fos = new FileOutputStream(jceksKeystore)) {
            ks.store(fos, PASSWORD.toCharArray());
        }
    }

    @Test
    public void testJceksToBcfksMigration() throws Exception {
        // Test migration from JCEKS to BCFKS
        File migratedKeystore = tempFolder.newFile("migrated.bcfks");

        // Run migration
        String[] args = {
            "-s",
            jceksKeystore.getAbsolutePath(),
            "-sp",
            PASSWORD,
            "-st",
            "JCEKS",
            "-t",
            migratedKeystore.getAbsolutePath(),
            "-tp",
            PASSWORD,
            "-tt",
            "BCFKS"
        };

        MigrateKeystore.main(args);

        // Verify the migrated keystore
        KeyStore migratedKs = KeyStore.getInstance("BCFKS", "BC");
        try (FileInputStream fis = new FileInputStream(migratedKeystore)) {
            migratedKs.load(fis, PASSWORD.toCharArray());
        }

        // Check that the secret key entry was migrated
        assertTrue("Secret key entry should exist", migratedKs.containsAlias("test-secret"));
        assertTrue("Should be a key entry", migratedKs.isKeyEntry("test-secret"));

        // Verify the key can be retrieved
        javax.crypto.SecretKey retrievedKey =
                (javax.crypto.SecretKey) migratedKs.getKey("test-secret", PASSWORD.toCharArray());
        assertNotNull("Retrieved key should not be null", retrievedKey);
        assertEquals("Key algorithm should be AES", "AES", retrievedKey.getAlgorithm());
    }

    @Test
    public void testBcfksToJceksMigration() throws Exception {
        // First create a BCFKS keystore
        KeyStore bcfksKs = KeyStore.getInstance("BCFKS", "BC");
        bcfksKs.load(null, PASSWORD.toCharArray());

        // Add a test secret key entry
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
        kg.init(128);
        javax.crypto.SecretKey secretKey = kg.generateKey();
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        bcfksKs.setEntry("test-secret", secretKeyEntry, new KeyStore.PasswordProtection(PASSWORD.toCharArray()));

        // Save the BCFKS keystore
        try (FileOutputStream fos = new FileOutputStream(bcfksKeystore)) {
            bcfksKs.store(fos, PASSWORD.toCharArray());
        }

        // Test migration from BCFKS to JCEKS
        File migratedKeystore = tempFolder.newFile("migrated.jceks");

        // Run migration
        String[] args = {
            "-s",
            bcfksKeystore.getAbsolutePath(),
            "-sp",
            PASSWORD,
            "-st",
            "BCFKS",
            "-t",
            migratedKeystore.getAbsolutePath(),
            "-tp",
            PASSWORD,
            "-tt",
            "JCEKS"
        };

        MigrateKeystore.main(args);

        // Verify the migrated keystore
        KeyStore migratedKs = KeyStore.getInstance("JCEKS");
        try (FileInputStream fis = new FileInputStream(migratedKeystore)) {
            migratedKs.load(fis, PASSWORD.toCharArray());
        }

        // Check that the secret key entry was migrated
        assertTrue("Secret key entry should exist", migratedKs.containsAlias("test-secret"));
        assertTrue("Should be a key entry", migratedKs.isKeyEntry("test-secret"));

        // Verify the key can be retrieved
        javax.crypto.SecretKey retrievedKey =
                (javax.crypto.SecretKey) migratedKs.getKey("test-secret", PASSWORD.toCharArray());
        assertNotNull("Retrieved key should not be null", retrievedKey);
        assertEquals("Key algorithm should be AES", "AES", retrievedKey.getAlgorithm());
    }

    @Test
    public void testJceksToPkcs12Migration() throws Exception {
        // Test migration from JCEKS to PKCS12
        File migratedKeystore = tempFolder.newFile("migrated.p12");

        // Run migration
        String[] args = {
            "-s",
            jceksKeystore.getAbsolutePath(),
            "-sp",
            PASSWORD,
            "-st",
            "JCEKS",
            "-t",
            migratedKeystore.getAbsolutePath(),
            "-tp",
            PASSWORD,
            "-tt",
            "PKCS12"
        };

        MigrateKeystore.main(args);

        // Verify the migrated keystore
        KeyStore migratedKs = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(migratedKeystore)) {
            migratedKs.load(fis, PASSWORD.toCharArray());
        }

        // Check that the secret key entry was migrated
        assertTrue("Secret key entry should exist", migratedKs.containsAlias("test-secret"));
        assertTrue("Should be a key entry", migratedKs.isKeyEntry("test-secret"));

        // Verify the key can be retrieved
        javax.crypto.SecretKey retrievedKey =
                (javax.crypto.SecretKey) migratedKs.getKey("test-secret", PASSWORD.toCharArray());
        assertNotNull("Retrieved key should not be null", retrievedKey);
        assertEquals("Key algorithm should be AES", "AES", retrievedKey.getAlgorithm());
    }

    @Test
    public void testDefaultMigrationBehavior() throws Exception {
        // Test that default behavior (JCEKS to JCEKS) works
        File migratedKeystore = tempFolder.newFile("migrated-default.jceks");

        // Run migration with minimal arguments (should default to BCFKS)
        String[] args = {
            "-s",
            jceksKeystore.getAbsolutePath(),
            "-sp",
            PASSWORD,
            "-t",
            migratedKeystore.getAbsolutePath(),
            "-tp",
            PASSWORD
        };

        MigrateKeystore.main(args);

        // Verify the migrated keystore (defaults to BCFKS)
        KeyStore migratedKs = KeyStore.getInstance("BCFKS", "BC");
        try (FileInputStream fis = new FileInputStream(migratedKeystore)) {
            migratedKs.load(fis, PASSWORD.toCharArray());
        }

        // Check that the secret key entry was migrated
        assertTrue("Secret key entry should exist", migratedKs.containsAlias("test-secret"));
        assertTrue("Should be a key entry", migratedKs.isKeyEntry("test-secret"));

        // Verify the key can be retrieved
        javax.crypto.SecretKey retrievedKey =
                (javax.crypto.SecretKey) migratedKs.getKey("test-secret", PASSWORD.toCharArray());
        assertNotNull("Retrieved key should not be null", retrievedKey);
        assertEquals("Key algorithm should be AES", "AES", retrievedKey.getAlgorithm());
    }

    @Test
    public void testKeystoreEntryCount() throws Exception {
        // Test that all entries are migrated correctly
        File migratedKeystore = tempFolder.newFile("migrated-count.bcfks");

        // Run migration
        String[] args = {
            "-s",
            jceksKeystore.getAbsolutePath(),
            "-sp",
            PASSWORD,
            "-st",
            "JCEKS",
            "-t",
            migratedKeystore.getAbsolutePath(),
            "-tp",
            PASSWORD,
            "-tt",
            "BCFKS"
        };

        MigrateKeystore.main(args);

        // Count entries in original keystore
        KeyStore originalKs = KeyStore.getInstance("JCEKS");
        try (FileInputStream fis = new FileInputStream(jceksKeystore)) {
            originalKs.load(fis, PASSWORD.toCharArray());
        }
        int originalCount = 0;
        Enumeration<String> originalAliases = originalKs.aliases();
        while (originalAliases.hasMoreElements()) {
            originalAliases.nextElement();
            originalCount++;
        }

        // Count entries in migrated keystore
        KeyStore migratedKs = KeyStore.getInstance("BCFKS", "BC");
        try (FileInputStream fis = new FileInputStream(migratedKeystore)) {
            migratedKs.load(fis, PASSWORD.toCharArray());
        }
        int migratedCount = 0;
        Enumeration<String> migratedAliases = migratedKs.aliases();
        while (migratedAliases.hasMoreElements()) {
            migratedAliases.nextElement();
            migratedCount++;
        }

        assertEquals("Number of entries should be preserved", originalCount, migratedCount);
    }
}
