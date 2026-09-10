/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.web.wicket;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;

import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;

public class AesCbcCryptTest {

    private static AesCbcCrypt crypt(byte b) {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, b);
        return new AesCbcCrypt(new SecretKeySpec(key, "AES"));
    }

    @Test
    public void testRoundTrip() {
        AesCbcCrypt crypt = crypt((byte) 1);
        String url = "wicket/bookmarkable/org.geoserver.web.GeoServerHomePage?0&param=value";
        assertEquals(url, crypt.decryptUrlSafe(crypt.encryptUrlSafe(url)));
    }

    /** Wicket re-renders a URL and compares it with the requested one, so the same input must encrypt the same way. */
    @Test
    public void testEncryptionIsRepeatable() {
        AesCbcCrypt crypt = crypt((byte) 1);
        assertEquals(crypt.encryptUrlSafe("a-page-url"), crypt.encryptUrlSafe("a-page-url"));
    }

    @Test
    public void testKeysDoNotShareCipherText() {
        assertNotEquals(
                crypt((byte) 1).encryptUrlSafe("a-page-url"), crypt((byte) 2).encryptUrlSafe("a-page-url"));
    }

    /**
     * Wicket's {@link org.apache.wicket.core.util.crypt.AbstractJceCrypt#decryptUrlSafe} answers null for anything it
     * cannot decrypt, and Wicket turns that into a rejected URL. CBC has no authentication tag, so a wrong key either
     * fails the padding check (null) or yields other bytes; what matters is that it never returns the original URL.
     */
    @Test
    public void testForeignCipherTextDoesNotDecrypt() {
        String encrypted = crypt((byte) 1).encryptUrlSafe("a-page-url");
        assertNotEquals("a-page-url", crypt((byte) 2).decryptUrlSafe(encrypted));
    }

    @Test
    public void testGarbageDecryptsToNull() {
        assertNull(crypt((byte) 1).decryptUrlSafe("not-base64-or-ciphertext"));
    }
}
