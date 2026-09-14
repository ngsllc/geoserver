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
import java.util.List;
import org.geoserver.data.test.SystemTestData;
import org.geoserver.platform.security.SecurityDefaults;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.test.GeoServerSystemTestSupport;
import org.geoserver.test.SystemTest;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * A deployment whose {@link SecurityDefaults} name another password encoder than the one a data directory was written
 * with gets that directory moved on the first start: the configuration password encoder is switched, the user group
 * services are switched and every password written again. This is the move a FIPS installation needs, done here with
 * the regular provider and the canned data directory, so that it is checked in every build.
 */
@Category(SystemTest.class)
public class PasswordEncoderDefaultsMigrationTest extends GeoServerSystemTestSupport {

    /** What the deployment asks for. Installed as a bean, the way the FIPS module installs its defaults. */
    public static class AesGcmDefaults implements SecurityDefaults {
        @Override
        public String get(Setting setting) {
            return switch (setting) {
                case CONFIG_PASSWORD_ENCODER, USER_GROUP_PASSWORD_ENCODER -> "aesGcmPasswordEncoder";
                default -> null;
            };
        }
    }

    private static boolean staged;

    @Override
    protected void setUpSpring(List<String> springContextLocations) {
        super.setUpSpring(springContextLocations);
        springContextLocations.add(getClass()
                .getResource(getClass().getSimpleName() + "-context.xml")
                .toString());
    }

    @Override
    protected void setUpTestData(SystemTestData testData) throws Exception {
        super.setUpTestData(testData);
        staged = false;
        if (!SystemTestData.canReadCannedSecurityDirectory()) {
            return; // the canned directory is not there to stage on
        }
        File security = new File(testData.getDataDirectoryRoot(), "security");
        LegacyDataDirectory.setSecretKey(
                new File(security, "geoserver.jceks"), "JCEKS", "ug:default:key", USER_GROUP_KEY);
        LegacyDataDirectory.stageCrypt2UserPasswords(security);
        // one password the migration cannot read, and one it must not corrupt
        LegacyDataDirectory.addUser(security, "damaged", LegacyPasswordFixtures.DAMAGED_CRYPT2);
        LegacyDataDirectory.addUser(security, "nonascii", LegacyPasswordFixtures.NON_ASCII_CRYPT2);
        staged = true;
    }

    @Before
    public void stagedOnly() {
        assumeTrue("the canned security directory cannot be read with this crypto provider", staged);
    }

    @Test
    public void testConfigurationPasswordEncoderIsSwitched() throws Exception {
        assertEquals(
                "aesGcmPasswordEncoder",
                getSecurityManager().getSecurityConfig().getConfigPasswordEncrypterName());
        File security = new File(getTestData().getDataDirectoryRoot(), "security");
        String config = Files.readString(new File(security, "config.xml").toPath(), StandardCharsets.UTF_8);
        assertTrue(config, config.contains("<configPasswordEncrypterName>aesGcmPasswordEncoder<"));

        ConfigurationPasswordEncryptionHelper helper = getSecurityManager().getConfigPasswordEncryptionHelper();
        assertTrue(helper.encode("fresh").startsWith("crypt3:"));
        // what the old encoders wrote is still read, that is what makes writing it again possible
        assertEquals(CANNED_PLAINTEXT, helper.decode(CANNED_CRYPT1));
        assertEquals(CANNED_PLAINTEXT, helper.decode(CANNED_CRYPT2));
    }

    @Test
    public void testUserGroupServicePasswordsAreWrittenAgain() throws Exception {
        File security = new File(getTestData().getDataDirectoryRoot(), "security");
        String config =
                Files.readString(new File(security, "usergroup/default/config.xml").toPath(), StandardCharsets.UTF_8);
        assertTrue(config, config.contains("<passwordEncoderName>aesGcmPasswordEncoder</passwordEncoderName>"));
        String users =
                Files.readString(new File(security, "usergroup/default/users.xml").toPath(), StandardCharsets.UTF_8);
        assertTrue(users, users.contains("password=\"crypt3:"));
        // everything readable moved; the one row that cannot be read is kept, see the test below
        assertFalse(
                users, users.replace(LegacyPasswordFixtures.DAMAGED_CRYPT2, "").contains("password=\"crypt2:"));

        GeoServerUserGroupService service = getSecurityManager().loadUserGroupService("default");
        assertEquals("aesGcmPasswordEncoder", service.getPasswordEncoderName());
        GeoServerUser admin = service.getUserByUsername("admin");
        assertNotNull(admin);
        GeoServerAesGcmPasswordEncoder encoder =
                getSecurityManager().loadPasswordEncoder(GeoServerAesGcmPasswordEncoder.class);
        encoder.initializeFor(service);
        assertTrue(encoder.isPasswordValid(admin.getPassword(), ADMIN_PASSWORD, null));
        assertFalse(encoder.isPasswordValid(admin.getPassword(), "not-" + ADMIN_PASSWORD, null));
    }

    /**
     * One password that cannot be read must not stop the migration, and must not stop GeoServer: reaching this test at
     * all means the context came up. The row is left as it was, so nothing that could still be read is destroyed.
     */
    @Test
    public void testUnreadablePasswordIsLeftAloneAndTheRestStillMigrates() throws Exception {
        File security = new File(getTestData().getDataDirectoryRoot(), "security");
        String users =
                Files.readString(new File(security, "usergroup/default/users.xml").toPath(), StandardCharsets.UTF_8);

        assertTrue("the unreadable row is kept verbatim", users.contains(LegacyPasswordFixtures.DAMAGED_CRYPT2));

        GeoServerUserGroupService service = getSecurityManager().loadUserGroupService("default");
        assertEquals(
                LegacyPasswordFixtures.DAMAGED_CRYPT2,
                service.getUserByUsername("damaged").getPassword());
        // and the readable ones went across regardless
        assertTrue(service.getUserByUsername("admin").getPassword().startsWith("crypt3:"));
    }

    /**
     * The migration must write back the same password it read. The character array methods of both encoders convert
     * through the platform default charset while a login compares UTF-8, so a password outside US-ASCII is where the
     * two disagree; on a JVM whose default charset is neither (Windows) that would lock the user out for good.
     */
    @Test
    public void testNonAsciiPasswordSurvivesTheMigration() throws Exception {
        GeoServerUserGroupService service = getSecurityManager().loadUserGroupService("default");
        GeoServerUser user = service.getUserByUsername("nonascii");
        assertNotNull(user);
        assertTrue(user.getPassword(), user.getPassword().startsWith("crypt3:"));

        GeoServerAesGcmPasswordEncoder encoder =
                getSecurityManager().loadPasswordEncoder(GeoServerAesGcmPasswordEncoder.class);
        encoder.initializeFor(service);
        assertEquals(LegacyPasswordFixtures.NON_ASCII_PASSWORD, encoder.decode(user.getPassword()));
        // this is the comparison a login actually makes
        assertTrue(
                "the migrated password must still validate",
                encoder.isPasswordValid(user.getPassword(), LegacyPasswordFixtures.NON_ASCII_PASSWORD, null));
    }

    /** The defaults said nothing about the keystore or the master password, so those stay as they were. */
    @Test
    public void testWhatTheDefaultsLeaveAloneStays() throws Exception {
        File security = new File(getTestData().getDataDirectoryRoot(), "security");
        assertTrue(new File(security, "geoserver.jceks").exists());
        assertFalse(new File(security, "geoserver.jceks.backup").exists());
        assertFalse(new File(security, "masterpw/default/passwd.backup").exists());
        String masterpw =
                Files.readString(new File(security, "masterpw/default/config.xml").toPath(), StandardCharsets.UTF_8);
        assertTrue(masterpw, masterpw.contains(URLMasterPasswordProvider.class.getName()));
    }
}
