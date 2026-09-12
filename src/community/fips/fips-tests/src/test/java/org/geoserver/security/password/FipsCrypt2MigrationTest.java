/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.geoserver.security.password.LegacyPasswordFixtures.ADMIN_PASSWORD;
import static org.geoserver.security.password.LegacyPasswordFixtures.CONFIG_CRYPT2;
import static org.geoserver.security.password.LegacyPasswordFixtures.CONFIG_KEY;
import static org.geoserver.security.password.LegacyPasswordFixtures.CONFIG_PLAINTEXT;
import static org.geoserver.security.password.LegacyPasswordFixtures.USER_GROUP_KEY;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Set;
import org.geoserver.data.test.SystemTestData;
import org.geoserver.fips.FipsSetup;
import org.geoserver.security.CryptoProviders;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.test.GeoServerSystemTestSupport;
import org.junit.Before;
import org.junit.Test;

/**
 * The passwords a regular GeoServer wrote with {@code crypt2} have to move to {@code crypt3} on the first start under
 * FIPS, although no FIPS provider has the cipher that wrote them: that is what {@link Pkcs12Pbe} is for. The keystore
 * and the master password are staged in the FIPS formats here, so this runs on every FIPS build; the move of those two
 * needs algorithms a FIPS system does not have and is covered by {@link FipsLegacyDataDirectoryTest}.
 */
public class FipsCrypt2MigrationTest extends GeoServerSystemTestSupport {

    @Before
    public void fipsClasspathOnly() {
        assumeTrue(FipsSetup.isFipsClasspath());
    }

    @Override
    protected void setUpTestData(SystemTestData testData) throws Exception {
        super.setUpTestData(testData);
        File security = new File(testData.getDataDirectoryRoot(), "security");
        LegacyDataDirectory.unpackCanned(
                security,
                Set.of(
                        "geoserver.jceks.default",
                        "geoserver.jceks.ibm",
                        "masterpw/default/config.xml",
                        "masterpw/default/passwd"));
        CryptoProviders.getProvider(); // BCFKS is the FIPS provider's format
        File keystore = new File(security, "geoserver.bcfks");
        LegacyDataDirectory.setSecretKey(keystore, "BCFKS", "config:password:key", CONFIG_KEY);
        LegacyDataDirectory.setSecretKey(keystore, "BCFKS", "ug:default:key", USER_GROUP_KEY);
        LegacyDataDirectory.stageAesGcmMasterPassword(security);
        LegacyDataDirectory.setConfigPasswordEncoder(security, "strongPbePasswordEncoder");
        LegacyDataDirectory.stageCrypt2UserPasswords(security);
    }

    @Test
    public void testConfigurationPasswordsMoveToCrypt3() throws Exception {
        assertEquals(
                "aesGcmPasswordEncoder",
                getSecurityManager().getSecurityConfig().getConfigPasswordEncrypterName());
        File security = new File(getTestData().getDataDirectoryRoot(), "security");
        String config = Files.readString(new File(security, "config.xml").toPath(), StandardCharsets.UTF_8);
        assertTrue(config, config.contains("<configPasswordEncrypterName>aesGcmPasswordEncoder<"));

        ConfigurationPasswordEncryptionHelper helper = getSecurityManager().getConfigPasswordEncryptionHelper();
        assertEquals(CONFIG_PLAINTEXT, helper.decode(CONFIG_CRYPT2));
        String fresh = helper.encode(CONFIG_PLAINTEXT);
        assertTrue(fresh, fresh.startsWith("crypt3:"));
        assertEquals(CONFIG_PLAINTEXT, helper.decode(fresh));
    }

    /** The old encoder reads, and only reads: nothing new may be written in a format the provider cannot handle. */
    @Test
    public void testCrypt2IsReadOnly() {
        GeoServerPBEPasswordEncoder crypt2 =
                (GeoServerPBEPasswordEncoder) getSecurityManager().loadPasswordEncoder("strongPbePasswordEncoder");
        assertTrue(crypt2.canDecode());
        assertFalse(crypt2.isCipherAvailable());

        assertEquals(CONFIG_PLAINTEXT, crypt2.decode(CONFIG_CRYPT2));
        assertTrue(crypt2.isPasswordValid(CONFIG_CRYPT2, CONFIG_PLAINTEXT, null));
        assertFalse(crypt2.isPasswordValid(CONFIG_CRYPT2, "store-secreT", null));
        IllegalStateException refused =
                assertThrows(IllegalStateException.class, () -> crypt2.encodePassword("new-secret", null));
        assertThat(refused.getMessage(), containsString("aesGcmPasswordEncoder"));
    }

    @Test
    public void testUserPasswordsMoveToCrypt3() throws Exception {
        File security = new File(getTestData().getDataDirectoryRoot(), "security");
        String config =
                Files.readString(new File(security, "usergroup/default/config.xml").toPath(), StandardCharsets.UTF_8);
        assertTrue(config, config.contains("<passwordEncoderName>aesGcmPasswordEncoder</passwordEncoderName>"));
        String users =
                Files.readString(new File(security, "usergroup/default/users.xml").toPath(), StandardCharsets.UTF_8);
        assertTrue(users, users.contains("password=\"crypt3:"));
        assertFalse(users, users.contains("password=\"crypt2:"));

        GeoServerUserGroupService service = getSecurityManager().loadUserGroupService("default");
        GeoServerUser admin = service.getUserByUsername("admin");
        assertNotNull(admin);
        GeoServerAesGcmPasswordEncoder encoder =
                getSecurityManager().loadPasswordEncoder(GeoServerAesGcmPasswordEncoder.class);
        encoder.initializeFor(service);
        assertTrue(encoder.isPasswordValid(admin.getPassword(), ADMIN_PASSWORD, null));
    }

    /** The keystore was already the FIPS one, so nothing was moved and nothing backed up. */
    @Test
    public void testKeyStoreIsLeftAlone() {
        File security = new File(getTestData().getDataDirectoryRoot(), "security");
        assertTrue(new File(security, "geoserver.bcfks").exists());
        assertFalse(new File(security, "geoserver.jceks").exists());
        assertFalse(new File(security, "geoserver.bcfks.backup").exists());
    }
}
