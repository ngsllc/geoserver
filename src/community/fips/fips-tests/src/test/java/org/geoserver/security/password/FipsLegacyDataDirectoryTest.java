/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.geoserver.security.password.LegacyPasswordFixtures.ADMIN_PASSWORD;
import static org.geoserver.security.password.LegacyPasswordFixtures.CANNED_CRYPT1;
import static org.geoserver.security.password.LegacyPasswordFixtures.CANNED_CRYPT2;
import static org.geoserver.security.password.LegacyPasswordFixtures.CANNED_PLAINTEXT;
import static org.geoserver.security.password.LegacyPasswordFixtures.USER_GROUP_KEY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Set;
import javax.crypto.Cipher;
import org.geoserver.data.test.SystemTestData;
import org.geoserver.fips.FipsSetup;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.KeyStoreProvider;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.test.GeoServerSystemTestSupport;
import org.junit.Before;
import org.junit.Test;

/**
 * The whole move: a data directory as a GeoServer 2.x left it, with a JCEKS keystore, a master password protected with
 * MD5/DES, the weak configuration password encoder and a user group service on {@code crypt2}, started once with the
 * FIPS module installed. Everything has to end up in the FIPS formats, with the old files kept as backups.
 *
 * <p>Reading the old keystore and master password takes JCEKS and MD5/DES from the JDK, which a FIPS system has
 * removed. That is why the move happens on a machine not yet in FIPS mode, and why this test only runs where the JDK
 * still offers them: with the {@code fips-test} profile, which stands in for a FIPS system, it is skipped. The FIPS
 * virtual machine runs it against the real thing.
 */
public class FipsLegacyDataDirectoryTest extends GeoServerSystemTestSupport {

    private static boolean staged;

    static boolean legacyFormatsReadable() {
        try {
            KeyStore.getInstance("JCEKS");
            Cipher.getInstance("PBEWithMD5AndDES");
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    @Override
    protected void setUpTestData(SystemTestData testData) throws Exception {
        super.setUpTestData(testData);
        staged = false;
        if (!FipsSetup.isFipsClasspath() || !legacyFormatsReadable()) {
            return;
        }
        File security = new File(testData.getDataDirectoryRoot(), "security");
        LegacyDataDirectory.unpackCanned(security, Set.of("geoserver.jceks.ibm"));
        File keystore = new File(security, "geoserver.jceks");
        Files.copy(new File(security, "geoserver.jceks.default").toPath(), keystore.toPath());
        LegacyDataDirectory.setSecretKey(keystore, "JCEKS", "ug:default:key", USER_GROUP_KEY);
        LegacyDataDirectory.stageCrypt2UserPasswords(security);
        staged = true;
    }

    @Before
    public void stagedOnly() {
        assumeTrue("the JDK here has no JCEKS or MD5/DES, as on a FIPS system: the move cannot run", staged);
    }

    @Test
    public void testKeyStoreMovesToBcfksWithItsKeys() throws Exception {
        File security = new File(getTestData().getDataDirectoryRoot(), "security");
        KeyStoreProvider keyStore = getSecurityManager().getKeyStoreProvider();
        assertEquals("geoserver.bcfks", keyStore.getResource().name());
        assertTrue(new File(security, "geoserver.bcfks").exists());
        assertTrue(new File(security, "geoserver.jceks.backup").exists());
        assertFalse(new File(security, "geoserver.jceks").exists());
        assertTrue(keyStore.hasConfigPasswordKey());
        assertTrue(keyStore.hasUserGroupKey("default"));
        // the configuration key kept its bytes: what was encrypted under it before still reads
        assertEquals(
                CANNED_PLAINTEXT,
                getSecurityManager().getConfigPasswordEncryptionHelper().decode(CANNED_CRYPT2));
    }

    @Test
    public void testMasterPasswordMovesToAesGcm() throws Exception {
        File security = new File(getTestData().getDataDirectoryRoot(), "security");
        String config =
                Files.readString(new File(security, "masterpw/default/config.xml").toPath(), StandardCharsets.UTF_8);
        assertTrue(config, config.contains(AesGcmMasterPasswordProvider.class.getName()));
        assertTrue(new File(security, "masterpw/default/passwd.backup").exists());
        // the same password unlocks the new keystore
        assertTrue(getSecurityManager().getKeyStoreProvider().isKeyStorePassword(LegacyDataDirectory.MASTER_PASSWORD));
    }

    @Test
    public void testConfigurationPasswordEncoderMovesToCrypt3() throws Exception {
        assertEquals(
                "aesGcmPasswordEncoder",
                getSecurityManager().getSecurityConfig().getConfigPasswordEncrypterName());
        ConfigurationPasswordEncryptionHelper helper = getSecurityManager().getConfigPasswordEncryptionHelper();
        assertTrue(helper.encode("fresh").startsWith("crypt3:"));
        // the weak encoder still reads here, through the JDK; a FIPS system would have lost these values
        assertEquals(CANNED_PLAINTEXT, helper.decode(CANNED_CRYPT1));
    }

    @Test
    public void testUserPasswordsMoveToCrypt3() throws Exception {
        File security = new File(getTestData().getDataDirectoryRoot(), "security");
        String users =
                Files.readString(new File(security, "usergroup/default/users.xml").toPath(), StandardCharsets.UTF_8);
        assertTrue(users, users.contains("password=\"crypt3:"));
        GeoServerUserGroupService service = getSecurityManager().loadUserGroupService("default");
        assertEquals("aesGcmPasswordEncoder", service.getPasswordEncoderName());
        GeoServerUser admin = service.getUserByUsername("admin");
        assertNotNull(admin);
        GeoServerAesGcmPasswordEncoder encoder =
                getSecurityManager().loadPasswordEncoder(GeoServerAesGcmPasswordEncoder.class);
        encoder.initializeFor(service);
        assertTrue(encoder.isPasswordValid(admin.getPassword(), ADMIN_PASSWORD, null));
    }
}
