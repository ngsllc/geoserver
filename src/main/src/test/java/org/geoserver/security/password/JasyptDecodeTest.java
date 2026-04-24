/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Base64;
import org.geotools.util.logging.Logging;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.junit.Test;

/** Test to verify Jasypt decryption behavior with different algorithm configurations. */
public class JasyptDecodeTest {

    private static final Logger LOGGER = Logging.getLogger(JasyptDecodeTest.class);

    private static final String PASSWORD = "testpassword";
    private static final byte[] KEY = "geoserver".getBytes(StandardCharsets.UTF_8);

    /**
     * Compatibility contract for pre-FIPS on-disk artifacts: data encrypted with an explicit PBEWithMD5AndDES (how
     * GeoServer 2.x wrote master-password files) must decode with Jasypt DEFAULTS, because URLMasterPasswordProvider's
     * legacy fallback relies on the default algorithm still being PBEWithMD5AndDES.
     *
     * <p>(A previous version of this test hardcoded a ciphertext read from the author's local webapp data dir — that
     * dir is gitignored, so the constant was not reproducible from the repo.)
     */
    @Test
    public void testDecodeActualTestData() throws Exception {
        // Encrypt the way GeoServer 2.x did: explicit legacy algorithm
        StandardPBEByteEncryptor legacyEncryptor = new StandardPBEByteEncryptor();
        legacyEncryptor.setAlgorithm("PBEWithMD5AndDES");
        legacyEncryptor.setPassword(new String(KEY));
        String legacyArtifact =
                Base64.encodeBase64String(legacyEncryptor.encrypt(PASSWORD.getBytes(StandardCharsets.UTF_8)));

        // Decode with Jasypt defaults (no algorithm set) — must still be PBEWithMD5AndDES-compatible
        StandardPBEByteEncryptor decryptor = new StandardPBEByteEncryptor();
        decryptor.setPassword(new String(KEY));
        byte[] decrypted = decryptor.decrypt(Base64.decodeBase64(legacyArtifact));
        String decoded = new String(decrypted, StandardCharsets.UTF_8);
        assertNotNull("Decoded value should not be null", decoded);
        assertTrue("Decoded value should not be empty", decoded.length() > 0);
        assertArrayEquals(PASSWORD.getBytes(StandardCharsets.UTF_8), decrypted);
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
        // Encode with FIPS algorithm
        StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
        encryptor.setAlgorithm("PBEWithHmacSHA256AndAES_128");
        encryptor.setSaltGenerator(new FipsRandomSaltGenerator());
        encryptor.setIvGenerator(new FipsRandomIvGenerator());
        encryptor.setPassword(new String(KEY));
        byte[] encrypted = encryptor.encrypt(PASSWORD.getBytes(StandardCharsets.UTF_8));
        String encoded = Base64.encodeBase64String(encrypted);
        LOGGER.log(Level.FINE, "Encoded with FIPS: " + encoded);

        // Decode with FIPS algorithm - also needs salt/IV generators set
        StandardPBEByteEncryptor decryptor = new StandardPBEByteEncryptor();
        decryptor.setAlgorithm("PBEWithHmacSHA256AndAES_128");
        decryptor.setSaltGenerator(new FipsRandomSaltGenerator());
        decryptor.setIvGenerator(new FipsRandomIvGenerator());
        decryptor.setPassword(new String(KEY));
        byte[] decrypted = decryptor.decrypt(Base64.decodeBase64(encoded));
        assertArrayEquals(PASSWORD.getBytes(StandardCharsets.UTF_8), decrypted);
    }

    @Test
    public void testLegacyDataWithDefaultDecode() throws Exception {
        // This is how data was encoded in original GeoServer (no algorithm set)
        StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
        encryptor.setPassword(new String(KEY));
        byte[] encrypted = encryptor.encrypt(PASSWORD.getBytes(StandardCharsets.UTF_8));
        String encoded = Base64.encodeBase64String(encrypted);
        LOGGER.log(Level.FINE, "Legacy encoded: " + encoded);

        // Try to decode with FIPS algorithm first (should fail)
        try {
            StandardPBEByteEncryptor decryptor = new StandardPBEByteEncryptor();
            decryptor.setAlgorithm("PBEWithHmacSHA256AndAES_128");
            decryptor.setPassword(new String(KEY));
            decryptor.decrypt(Base64.decodeBase64(encoded));
            fail("Should have failed to decode with FIPS algorithm");
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Expected failure with FIPS: " + e.getClass().getSimpleName());
        }

        // Decode with default (no algorithm set) - should work
        StandardPBEByteEncryptor decryptor = new StandardPBEByteEncryptor();
        decryptor.setPassword(new String(KEY));
        byte[] decrypted = decryptor.decrypt(Base64.decodeBase64(encoded));
        assertArrayEquals(PASSWORD.getBytes(StandardCharsets.UTF_8), decrypted);
    }
}
