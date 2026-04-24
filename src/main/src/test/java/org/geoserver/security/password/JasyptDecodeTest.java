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
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.geotools.util.logging.Logging;
import org.junit.Test;

/** Test to verify Jasypt decryption behavior with different algorithm configurations. */
public class JasyptDecodeTest {

    private static final Logger LOGGER = Logging.getLogger(JasyptDecodeTest.class);

    private static final String PASSWORD = "testpassword";
    private static final byte[] KEY = "geoserver".getBytes(StandardCharsets.UTF_8);

    /**
     * Verify that the bundled master password file can be decoded with Jasypt defaults
     * (PBEWithMD5AndDES). If the file format or key changes, this test must be updated.
     */
    @Test
    public void testDecodeActualTestData() throws Exception {
        // This is the actual password from src/web/app/src/main/webapp/data/security/masterpw/default/passwd
        String testDataPassword = "PNscY3AJUiCvPltKjaZ+KAg9bDHm1CNxfxIEUl0caSx/1hfOAXSeMyV7yD9cu0FM";

        // Try with Jasypt default (no algorithm set = PBEWithMD5AndDES)
        StandardPBEByteEncryptor decryptor = new StandardPBEByteEncryptor();
        decryptor.setPassword(new String(KEY));
        byte[] decrypted = decryptor.decrypt(Base64.decodeBase64(testDataPassword));
        // The decrypted value should be a non-empty UTF-8 string
        String decoded = new String(decrypted, StandardCharsets.UTF_8);
        assertNotNull("Decoded value should not be null", decoded);
        assertTrue("Decoded value should not be empty", decoded.length() > 0);
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
