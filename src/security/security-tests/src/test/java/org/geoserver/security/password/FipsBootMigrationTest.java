/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.geoserver.security.SecurityUtils.toChars;
import static org.geoserver.security.password.LegacyPasswordFixtures.CRYPT2;
import static org.geoserver.security.password.LegacyPasswordFixtures.PLAINTEXT;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.geoserver.data.test.SystemTestData;
import org.geoserver.security.FIPSModuleStatus;
import org.geoserver.security.FipsRuntime;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.KeyStoreProviderImpl;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.test.GeoServerSystemTestSupport;
import org.geoserver.test.SystemTest;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * The documented migration: start GeoServer with {@code FIPS_MODE=true} on a data directory created by an earlier
 * version (JCEKS keystore, MD5/DES master password file, weak configuration password encoder, a user group service
 * whose passwords are encrypted with the {@code crypt2} PKCS#12 encoder). One start must move everything to the FIPS
 * approved formats (BCFKS, AES-GCM master password, {@code crypt3} everywhere) while keeping the old values readable,
 * and must do so through the pure JCA reader for {@code crypt2}, since approved-only mode withdraws its cipher.
 */
@Category(SystemTest.class)
public class FipsBootMigrationTest extends GeoServerSystemTestSupport {

    static final String USER_PASSWORD = "geoserver";
    static final String USER_GROUP_KEY = "a-forty-character-user-group-key-0123456";

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
        // FIPS mode put the provider first; leave the JVM the way a non-FIPS test class expects it
        Security.removeProvider(KeyStoreProviderImpl.BCFIPS_PROVIDER);
        FipsRuntime.registerProvider();
    }

    @Override
    protected void setUpTestData(SystemTestData testData) throws Exception {
        super.setUpTestData(testData);
        // in FIPS mode the harness stages no keystore at all; stage the legacy JCEKS one like an upgrading site has
        File security = new File(testData.getDataDirectoryRoot(), "security");
        File keystore = new File(security, "geoserver.jceks");
        Files.copy(new File(security, "geoserver.jceks.default").toPath(), keystore.toPath());
        stageCrypt2UserPasswords(security, keystore);
    }

    /**
     * Gives the default user group service a key and switches it to the {@code crypt2} encoder, with the admin password
     * encrypted the way an earlier GeoServer wrote it: jasypt, {@code PBEWITHSHA256AND256BITAES-BC}, the stored key
     * bytes as password, no IV generator.
     */
    private static void stageCrypt2UserPasswords(File security, File keystoreFile) throws Exception {
        char[] masterPassword = "geoserver".toCharArray();
        KeyStore ks = KeyStore.getInstance("JCEKS");
        try (FileInputStream in = new FileInputStream(keystoreFile)) {
            ks.load(in, masterPassword);
        }
        byte[] keyBytes = USER_GROUP_KEY.getBytes(StandardCharsets.US_ASCII);
        ks.setEntry(
                "ug:default:key",
                new KeyStore.SecretKeyEntry(new SecretKeySpec(keyBytes, "PBE")),
                new KeyStore.PasswordProtection(masterPassword));
        try (FileOutputStream out = new FileOutputStream(keystoreFile)) {
            ks.store(out, masterPassword);
        }

        assertTrue(KeyStoreProviderImpl.ensureBcFipsProviderRegistered());
        StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
        encryptor.setAlgorithm(KeyStoreProviderImpl.FIPS_PBE_ALGORITHM);
        encryptor.setProviderName(KeyStoreProviderImpl.BCFIPS_PROVIDER);
        encryptor.setPasswordCharArray(toChars(keyBytes));
        String crypt2 = "crypt2:"
                + Base64.getEncoder().encodeToString(encryptor.encrypt(USER_PASSWORD.getBytes(StandardCharsets.UTF_8)));

        File users = new File(security, "usergroup/default/users.xml");
        String xml = Files.readString(users.toPath(), StandardCharsets.UTF_8);
        assertTrue(xml.contains("password=\"digest1:"));
        Files.writeString(
                users.toPath(), xml.replaceFirst("password=\"digest1:[^\"]*\"", "password=\"" + crypt2 + "\""));

        File config = new File(security, "usergroup/default/config.xml");
        String configXml = Files.readString(config.toPath(), StandardCharsets.UTF_8);
        assertTrue(configXml.contains("<passwordEncoderName>digestPasswordEncoder</passwordEncoderName>"));
        Files.writeString(
                config.toPath(),
                configXml.replace(
                        "<passwordEncoderName>digestPasswordEncoder</passwordEncoderName>",
                        "<passwordEncoderName>strongPbePasswordEncoder</passwordEncoderName>"));
    }

    @Test
    public void testLegacyDirectoryMigratesOnFipsBoot() throws Exception {
        assertTrue(KeyStoreProviderImpl.isFipsMode());
        assertEquals("first", FipsRuntime.describeProviderPosition());
        assertEquals(
                KeyStoreProviderImpl.BCFIPS_PROVIDER,
                FipsRuntime.secureRandom().getProvider().getName());
        File security = new File(getTestData().getDataDirectoryRoot(), "security");

        // configuration password encoder switched from the weak encoder to AES-GCM, in memory and on disk
        GeoServerAesGcmPasswordEncoder gcm =
                getSecurityManager().loadPasswordEncoder(GeoServerAesGcmPasswordEncoder.class);
        assertNotNull(gcm);
        assertEquals("crypt3", gcm.getPrefix());
        assertEquals(gcm.getName(), getSecurityManager().getSecurityConfig().getConfigPasswordEncrypterName());
        String configXml = Files.readString(new File(security, "config.xml").toPath(), StandardCharsets.UTF_8);
        assertTrue(
                configXml.contains("<configPasswordEncrypterName>" + gcm.getName() + "</configPasswordEncrypterName>"));

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

        // master password re-encrypted with AES-GCM, backup kept, same secret, no temp files
        File passwd = new File(security, "masterpw/default/passwd");
        File backup = new File(security, "masterpw/default/passwd.backup");
        assertTrue(backup.exists());
        byte[] plainNew = decryptGcm(passwd);
        assertTrue(plainNew.length > 0);
        assertArrayEquals(decryptLegacy(backup), plainNew);
        assertEquals(0, new File(security, "masterpw/default").list((d, n) -> n.endsWith(".tmp")).length);

        // crypt2 values written by the earlier version decrypt, through the pure JCA reader, and nothing new is
        // written in that format any more
        GeoServerPBEPasswordEncoder strong =
                getSecurityManager().loadPasswordEncoder(GeoServerPBEPasswordEncoder.class, true, true);
        assertEquals(PLAINTEXT, strong.decode(CRYPT2));
        assertTrue(strong.isPasswordValid(CRYPT2, PLAINTEXT, null));
        assertFalse(strong.isPasswordValid(CRYPT2, "not-the-password", null));
        assertEquals(
                PLAINTEXT,
                getSecurityManager().getConfigPasswordEncryptionHelper().decode(CRYPT2));
        IllegalStateException refused =
                assertThrows(IllegalStateException.class, () -> strong.encodePassword("new-secret", null));
        assertTrue(refused.getMessage(), refused.getMessage().contains("crypt3"));

        // new values round trip through crypt3
        String encoded = gcm.encodePassword("new-secret", null);
        assertTrue(encoded, encoded.startsWith("crypt3:"));
        assertEquals("new-secret", gcm.decode(encoded));
        assertTrue(gcm.isPasswordValid(encoded, "new-secret", null));
        assertFalse(gcm.isPasswordValid(encoded, "new-secret-not", null));
        assertFalse("a corrupt value is a failed match, not an error", gcm.isPasswordValid("crypt3:AAAA", "x", null));

        // the weak encoder reads (this JVM still offers MD5/DES) but refuses to write in FIPS mode
        GeoServerPBEPasswordEncoder weak =
                (GeoServerPBEPasswordEncoder) getSecurityManager().loadPasswordEncoder("pbePasswordEncoder");
        assertThrows(IllegalStateException.class, () -> weak.encodePassword("x", null));

        // the user group service was switched to crypt3 and its passwords re-encrypted, still valid
        String ugConfig =
                Files.readString(new File(security, "usergroup/default/config.xml").toPath(), StandardCharsets.UTF_8);
        assertTrue(ugConfig, ugConfig.contains("<passwordEncoderName>" + gcm.getName() + "</passwordEncoderName>"));
        String users =
                Files.readString(new File(security, "usergroup/default/users.xml").toPath(), StandardCharsets.UTF_8);
        assertTrue(users, users.contains("password=\"crypt3:"));
        assertFalse(users, users.contains("password=\"crypt2:"));
        GeoServerUserGroupService service = getSecurityManager().loadUserGroupService("default");
        assertEquals(gcm.getName(), service.getPasswordEncoderName());
        GeoServerUser admin = service.getUserByUsername("admin");
        assertNotNull(admin);
        assertTrue(admin.getPassword(), admin.getPassword().startsWith("crypt3:"));
        GeoServerAesGcmPasswordEncoder forService =
                getSecurityManager().loadPasswordEncoder(GeoServerAesGcmPasswordEncoder.class);
        forService.initializeFor(service);
        assertTrue(forService.isPasswordValid(admin.getPassword(), USER_PASSWORD, null));
        assertEquals(USER_PASSWORD, forService.decode(admin.getPassword()));

        // the status page reports what is actually in force
        String status = new FIPSModuleStatus().getMessage().orElse("");
        assertTrue(status, status.contains("FIPS mode: ENABLED"));
        assertTrue(status, status.contains("Crypto provider: first"));
        assertTrue(status, status.contains("Random source: DEFAULT (BCFIPS)"));
        assertTrue(status, status.contains("Keystore type: BCFKS"));
    }

    private static byte[] decryptGcm(File file) throws Exception {
        byte[] stored = Files.readAllBytes(file.toPath());
        byte[] salt = Arrays.copyOfRange(stored, 0, AesGcmCipher.SALT_LENGTH);
        SecretKey key = AesGcmCipher.deriveKey(new URLMasterPasswordProvider().key(), salt);
        return AesGcmCipher.decrypt(key, Arrays.copyOfRange(stored, AesGcmCipher.SALT_LENGTH, stored.length));
    }

    private static byte[] decryptLegacy(File file) throws Exception {
        StandardPBEByteEncryptor decryptor =
                URLMasterPasswordProvider.newEncryptor(URLMasterPasswordProvider.LEGACY_PBE_ALGORITHM);
        decryptor.setPasswordCharArray(new URLMasterPasswordProvider().key());
        return decryptor.decrypt(
                org.apache.commons.codec.binary.Base64.decodeBase64(Files.readAllBytes(file.toPath())));
    }
}
