/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.geoserver.security.password.LegacyPasswordFixtures.CRYPT2;
import static org.geoserver.security.password.LegacyPasswordFixtures.PLAINTEXT;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import javax.crypto.SecretKey;
import org.apache.commons.codec.binary.Base64;
import org.geoserver.data.test.SystemTestData;
import org.geoserver.security.KeyStoreProviderImpl;
import org.geoserver.test.GeoServerSystemTestSupport;
import org.geoserver.test.SystemTest;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * The documented migration: start GeoServer with {@code FIPS_MODE=true} on a data directory created by an earlier
 * version (JCEKS keystore, MD5/DES master password file, weak configuration password encoder). One start must migrate
 * the keystore and the master password, switch the configuration password encoder, and keep the strong passwords stored
 * by the earlier version readable.
 */
@Category(SystemTest.class)
public class FipsBootMigrationTest extends GeoServerSystemTestSupport {

    @BeforeClass
    public static void enableFipsMode() {
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");
        // SystemTestData caches the keystore type across test classes sharing this JVM; reset it so
        // setUpSecurity() below picks BCFKS instead of a type cached by an earlier, non-FIPS test class
        SystemTestData.resetCachedKeystoreType();
    }

    @AfterClass
    public static void disableFipsMode() {
        System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        SystemTestData.resetCachedKeystoreType();
    }

    @Override
    protected void setUpTestData(SystemTestData testData) throws Exception {
        super.setUpTestData(testData);
        // in FIPS mode the harness stages no keystore at all; stage the legacy JCEKS one like an upgrading site has
        File security = new File(testData.getDataDirectoryRoot(), "security");
        Files.copy(
                new File(security, "geoserver.jceks.default").toPath(), new File(security, "geoserver.jceks").toPath());
    }

    @Test
    public void testLegacyDirectoryMigratesOnFipsBoot() throws Exception {
        assertTrue(KeyStoreProviderImpl.isFipsMode());
        File security = new File(getTestData().getDataDirectoryRoot(), "security");

        // configuration password encoder switched from the weak encoder, in memory and on disk
        GeoServerPBEPasswordEncoder strong =
                getSecurityManager().loadPasswordEncoder(GeoServerPBEPasswordEncoder.class, true, true);
        assertEquals(strong.getName(), getSecurityManager().getSecurityConfig().getConfigPasswordEncrypterName());
        String configXml = Files.readString(new File(security, "config.xml").toPath(), StandardCharsets.UTF_8);
        assertTrue(configXml.contains(
                "<configPasswordEncrypterName>" + strong.getName() + "</configPasswordEncrypterName>"));

        // keystore migrated to BCFKS with the legacy key preserved and readable
        assertEquals(
                "geoserver.bcfks",
                getSecurityManager().getKeyStoreProvider().getResource().name());
        assertTrue(new File(security, "geoserver.bcfks").exists());
        assertTrue(new File(security, "geoserver.jceks.backup").exists());
        SecretKey key = getSecurityManager().getKeyStoreProvider().getSecretKey(KeyStoreProviderImpl.CONFIGPASSWORDKEY);
        assertNotNull(key);
        assertEquals(KeyStoreProviderImpl.LEGACY_SECRET_KEY_ALGORITHM, key.getAlgorithm());
        assertEquals(40, key.getEncoded().length);
        assertTrue(GeoServerPBEPasswordEncoder.isLegacyKey(key));

        // master password re-encrypted with the FIPS algorithm, backup kept, same secret, no temp files
        File passwd = new File(security, "masterpw/default/passwd");
        File backup = new File(security, "masterpw/default/passwd.backup");
        assertTrue(backup.exists());
        byte[] plainNew = decrypt(passwd, URLMasterPasswordProvider.FIPS_PBE_ALGORITHM);
        assertTrue(plainNew.length > 0);
        assertArrayEquals(decrypt(backup, URLMasterPasswordProvider.LEGACY_PBE_ALGORITHM), plainNew);
        assertEquals(0, new File(security, "masterpw/default").list((d, n) -> n.endsWith(".tmp")).length);

        // strong passwords written by the earlier version decrypt, new ones round trip
        assertEquals(PLAINTEXT, strong.decode(CRYPT2));
        assertTrue(strong.isPasswordValid(CRYPT2, PLAINTEXT, null));
        assertEquals(
                PLAINTEXT,
                getSecurityManager().getConfigPasswordEncryptionHelper().decode(CRYPT2));
        String encoded = strong.encodePassword("new-secret", null);
        assertTrue(encoded, encoded.startsWith("crypt2:"));
        assertEquals("new-secret", strong.decode(encoded));

        // the weak encoder is refused in FIPS mode, with a message that says so
        RuntimeException e = assertThrows(
                RuntimeException.class, () -> getSecurityManager().loadPasswordEncoder("pbePasswordEncoder"));
        assertTrue(e.getMessage(), e.getMessage().contains("not available in FIPS mode"));
        assertFalse(getSecurityManager().getKeyStoreProvider().containsAlias("does-not-exist"));
    }

    private static byte[] decrypt(File file, String algorithm) throws Exception {
        StandardPBEByteEncryptor decryptor = URLMasterPasswordProvider.newEncryptor(algorithm);
        decryptor.setPasswordCharArray(new URLMasterPasswordProvider().key());
        return decryptor.decrypt(Base64.decodeBase64(Files.readAllBytes(file.toPath())));
    }
}
