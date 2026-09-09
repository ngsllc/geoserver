/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Base64;
import org.geoserver.security.KeyStoreProviderImpl;
import org.geotools.util.logging.Logging;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.junit.BeforeClass;
import org.junit.Test;

/** Test to verify Jasypt decryption behavior with different algorithm configurations. */
public class JasyptDecodeTest {

    private static final Logger LOGGER = Logging.getLogger(JasyptDecodeTest.class);

    private static final String PASSWORD = "testpassword";
    private static final byte[] KEY = "geoserver".getBytes(StandardCharsets.UTF_8);

    @BeforeClass
    public static void registerBcFips() {
        // The FIPS algorithm is provided by BCFIPS only, exactly like production code this test must register it
        assertTrue("bc-fips must be on the test classpath", KeyStoreProviderImpl.ensureBcFipsProviderRegistered());
    }

    /**
     * Master password file content ("geoserver") as written by GeoServer before FIPS support was added, that is
     * encrypted with the Jasypt default PBEWithMD5AndDES and the provider's internal key.
     */
    private static final String LEGACY_FIXTURE = "GsqggqcCoGxI+pEyUx41NzY03DvYwBbt";

    /** Same content as written by earlier FIPS builds, which used PBEWithHmacSHA256AndAES_128 (SunJCE). */
    private static final String PREVIOUS_FIPS_FIXTURE =
            "hWh7fueafM+AaprqKysMzWizbp/GOjmatHJ4kO/7wQCB/LV0W7Fwa+LDhp9531MS";

    /** Existing master password files must remain readable; if the key or permutation changes these fail on purpose. */
    @Test
    public void testDecodeLegacyFixture() throws Exception {
        assertEquals("geoserver", decodeFixture(LEGACY_FIXTURE, URLMasterPasswordProvider.LEGACY_PBE_ALGORITHM));
    }

    @Test
    public void testDecodePreviousFipsFixture() throws Exception {
        assertEquals(
                "geoserver",
                decodeFixture(PREVIOUS_FIPS_FIXTURE, URLMasterPasswordProvider.PREVIOUS_FIPS_PBE_ALGORITHM));
    }

    /**
     * In FIPS mode (as set by FIPS_MODE=true on a host without OS level FIPS, the documented migration setup) the
     * provider must still read files written with the previous and legacy algorithms so it can migrate them.
     */
    @Test
    public void testDecodeChainInFipsMode() throws Exception {
        URLMasterPasswordProviderConfig config = new URLMasterPasswordProviderConfig();
        config.setName("test");
        config.setEncrypting(true);
        URLMasterPasswordProvider provider = new URLMasterPasswordProvider();
        provider.initializeFromConfig(config);

        String oldValue = System.getProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");
        try {
            assertTrue(KeyStoreProviderImpl.isFipsMode());
            byte[] utf8 = "geoserver".getBytes(StandardCharsets.UTF_8);
            // current algorithm round trip
            assertArrayEquals(utf8, provider.decode(provider.encode("geoserver".toCharArray())));
            // files from earlier builds are still readable (migration itself is skipped, no security manager here)
            assertArrayEquals(utf8, provider.decode(LEGACY_FIXTURE.getBytes(StandardCharsets.US_ASCII)));
            assertArrayEquals(utf8, provider.decode(PREVIOUS_FIPS_FIXTURE.getBytes(StandardCharsets.US_ASCII)));
        } finally {
            if (oldValue == null) {
                System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
            } else {
                System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, oldValue);
            }
        }
    }

    private static String decodeFixture(String fixture, String algorithm) {
        StandardPBEByteEncryptor decryptor = URLMasterPasswordProvider.newEncryptor(algorithm);
        decryptor.setPasswordCharArray(new URLMasterPasswordProvider().key());
        return new String(decryptor.decrypt(Base64.decodeBase64(fixture)), StandardCharsets.UTF_8);
    }

    @Test
    public void testDefaultEncodeDecode() throws Exception {
        // Encode with default algorithm (PBEWithMD5AndDES)
        StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
        encryptor.setPassword(new String(KEY));
        byte[] encrypted = encryptor.encrypt(PASSWORD.getBytes(StandardCharsets.UTF_8));
        String encoded = Base64.encodeBase64String(encrypted);
        LOGGER.log(Level.FINE, "Encoded with default: " + encoded);

        // Decode with default algorithm
        StandardPBEByteEncryptor decryptor = new StandardPBEByteEncryptor();
        decryptor.setPassword(new String(KEY));
        byte[] decrypted = decryptor.decrypt(Base64.decodeBase64(encoded));
        assertArrayEquals(PASSWORD.getBytes(StandardCharsets.UTF_8), decrypted);
    }

    @Test
    public void testFipsEncodeDecode() throws Exception {
        // Encode with FIPS algorithm, using the exact same encryptor setup as URLMasterPasswordProvider
        StandardPBEByteEncryptor encryptor =
                URLMasterPasswordProvider.newEncryptor(URLMasterPasswordProvider.FIPS_PBE_ALGORITHM);
        encryptor.setPassword(new String(KEY));
        byte[] encrypted = encryptor.encrypt(PASSWORD.getBytes(StandardCharsets.UTF_8));
        String encoded = Base64.encodeBase64String(encrypted);
        LOGGER.log(Level.FINE, "Encoded with FIPS: " + encoded);

        // Decode with FIPS algorithm
        StandardPBEByteEncryptor decryptor =
                URLMasterPasswordProvider.newEncryptor(URLMasterPasswordProvider.FIPS_PBE_ALGORITHM);
        decryptor.setPassword(new String(KEY));
        byte[] decrypted = decryptor.decrypt(Base64.decodeBase64(encoded));
        assertArrayEquals(PASSWORD.getBytes(StandardCharsets.UTF_8), decrypted);
    }

    @Test
    public void testPreviousFipsAlgorithmRoundTrip() throws Exception {
        // The algorithm used by earlier FIPS builds is provided by SunJCE and must keep working for migration
        StandardPBEByteEncryptor encryptor =
                URLMasterPasswordProvider.newEncryptor(URLMasterPasswordProvider.PREVIOUS_FIPS_PBE_ALGORITHM);
        encryptor.setPassword(new String(KEY));
        byte[] encrypted = encryptor.encrypt(PASSWORD.getBytes(StandardCharsets.UTF_8));

        StandardPBEByteEncryptor decryptor =
                URLMasterPasswordProvider.newEncryptor(URLMasterPasswordProvider.PREVIOUS_FIPS_PBE_ALGORITHM);
        decryptor.setPassword(new String(KEY));
        assertArrayEquals(PASSWORD.getBytes(StandardCharsets.UTF_8), decryptor.decrypt(encrypted));

        // and its ciphertext must be rejected by the current algorithm, otherwise the fallback chain is unsafe
        StandardPBEByteEncryptor current =
                URLMasterPasswordProvider.newEncryptor(URLMasterPasswordProvider.FIPS_PBE_ALGORITHM);
        current.setPassword(new String(KEY));
        assertThrows(EncryptionOperationNotPossibleException.class, () -> current.decrypt(encrypted));
    }

    @Test
    public void testLegacyDataWithDefaultDecode() throws Exception {
        // This is how data was encoded in original GeoServer (no algorithm set)
        StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
        encryptor.setPassword(new String(KEY));
        byte[] encrypted = encryptor.encrypt(PASSWORD.getBytes(StandardCharsets.UTF_8));
        String encoded = Base64.encodeBase64String(encrypted);
        LOGGER.log(Level.FINE, "Legacy encoded: " + encoded);

        // Decoding with the FIPS algorithm must fail at decryption time (the algorithm itself is available)
        StandardPBEByteEncryptor fipsDecryptor =
                URLMasterPasswordProvider.newEncryptor(URLMasterPasswordProvider.FIPS_PBE_ALGORITHM);
        fipsDecryptor.setPassword(new String(KEY));
        assertThrows(
                EncryptionOperationNotPossibleException.class,
                () -> fipsDecryptor.decrypt(Base64.decodeBase64(encoded)));

        // Decode with default (no algorithm set) - should work
        StandardPBEByteEncryptor decryptor = new StandardPBEByteEncryptor();
        decryptor.setPassword(new String(KEY));
        byte[] decrypted = decryptor.decrypt(Base64.decodeBase64(encoded));
        assertArrayEquals(PASSWORD.getBytes(StandardCharsets.UTF_8), decrypted);
    }
}
