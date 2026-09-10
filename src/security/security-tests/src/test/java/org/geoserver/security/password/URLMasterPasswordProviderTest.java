/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.apache.commons.io.IOUtils;
import org.geoserver.security.GeoServerSecurityTestSupport;
import org.geoserver.test.SystemTest;
import org.geotools.util.URLs;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(SystemTest.class)
public class URLMasterPasswordProviderTest extends GeoServerSecurityTestSupport {

    @Test
    public void testEncryption() throws Exception {
        File tmp = newPasswordFile();
        URLMasterPasswordProvider mpp = newProvider(tmp);
        mpp.doSetMasterPassword("geoserver".toCharArray());

        String encoded = IOUtils.toString(new FileInputStream(tmp), StandardCharsets.UTF_8);
        assertNotEquals("geoserver", encoded);

        char[] passwd = mpp.doGetMasterPassword();
        assertArrayEquals("geoserver".toCharArray(), passwd);

        // written with the current algorithm, so no migration must have happened
        assertFalse(new File(tmp.getPath() + ".backup").exists());
        assertNoTempFiles(tmp);
    }

    @Test
    public void testLegacyFileIsMigrated() throws Exception {
        // the legacy algorithm is blocked by the JVM on an OS-level FIPS host
        try {
            javax.crypto.Cipher.getInstance(URLMasterPasswordProvider.LEGACY_PBE_ALGORITHM);
        } catch (Exception e) {
            org.junit.Assume.assumeNoException("legacy PBE algorithm not available on this JVM", e);
        }
        assertMigratedFrom(URLMasterPasswordProvider.LEGACY_PBE_ALGORITHM);
    }

    @Test
    public void testPreviousFipsFileIsMigrated() throws Exception {
        assertMigratedFrom(URLMasterPasswordProvider.PREVIOUS_FIPS_PBE_ALGORITHM);
    }

    @Test
    public void testEarlierFipsFileIsMigrated() throws Exception {
        // written by the earlier FIPS builds with the BC-FIPS PKCS#12 cipher, read back through Pkcs12Pbe
        assertMigratedFrom(URLMasterPasswordProvider.FIPS_PBE_ALGORITHM);
    }

    @Test
    public void testCurrentFormatIsAesGcm() throws Exception {
        File tmp = newPasswordFile();
        URLMasterPasswordProvider mpp = newProvider(tmp);
        mpp.doSetMasterPassword("geoserver".toCharArray());
        byte[] stored = Files.readAllBytes(tmp.toPath());
        byte[] salt = java.util.Arrays.copyOfRange(stored, 0, AesGcmCipher.SALT_LENGTH);
        javax.crypto.SecretKey key = AesGcmCipher.deriveKey(mpp.key(), salt);
        byte[] plain = AesGcmCipher.decrypt(
                key, java.util.Arrays.copyOfRange(stored, AesGcmCipher.SALT_LENGTH, stored.length));
        assertArrayEquals("geoserver".getBytes(StandardCharsets.UTF_8), plain);
    }

    /**
     * Writes a master password file with the given (non current) algorithm, reads it back and checks the provider both
     * returned the right password and re-encrypted the file with the current algorithm.
     */
    private void assertMigratedFrom(String algorithm) throws Exception {
        File tmp = newPasswordFile();
        URLMasterPasswordProvider mpp = newProvider(tmp);
        Files.write(tmp.toPath(), mpp.encodeWithAlgorithm("geoserver".toCharArray(), algorithm));
        byte[] before = Files.readAllBytes(tmp.toPath());

        assertArrayEquals("geoserver".toCharArray(), mpp.doGetMasterPassword());

        // file rewritten with the current algorithm, original kept as backup
        byte[] after = Files.readAllBytes(tmp.toPath());
        assertFalse("file should have been re-encrypted", java.util.Arrays.equals(before, after));
        File backup = new File(tmp.getPath() + ".backup");
        assertTrue(backup.exists());
        assertArrayEquals(before, Files.readAllBytes(backup.toPath()));
        assertNoTempFiles(tmp);

        // second read succeeds directly with the current algorithm and does not touch the file again
        assertArrayEquals("geoserver".toCharArray(), mpp.doGetMasterPassword());
        assertArrayEquals(after, Files.readAllBytes(tmp.toPath()));
    }

    private File newPasswordFile() throws Exception {
        File dir = Files.createTempDirectory(new File("target").toPath(), "masterpw")
                .toFile();
        return new File(dir, "passwd").getCanonicalFile();
    }

    private URLMasterPasswordProvider newProvider(File file) throws Exception {
        URLMasterPasswordProviderConfig config = new URLMasterPasswordProviderConfig();
        config.setName("test");
        config.setReadOnly(false);
        config.setLoginEnabled(true);
        config.setClassName(URLMasterPasswordProvider.class.getCanonicalName());
        config.setURL(URLs.fileToUrl(file));
        config.setEncrypting(true);

        URLMasterPasswordProvider mpp = new URLMasterPasswordProvider();
        mpp.setSecurityManager(getSecurityManager());
        mpp.initializeFromConfig(config);
        mpp.setName(config.getName());
        return mpp;
    }

    private void assertNoTempFiles(File passwordFile) {
        String[] leftovers = passwordFile.getParentFile().list((dir, name) -> name.endsWith(".tmp"));
        assertTrue("temporary files left behind: " + String.join(", ", leftovers), leftovers.length == 0);
    }
}
