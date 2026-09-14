/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import org.junit.Test;

/**
 * The reader has to agree with what the regular BouncyCastle provider wrote through jasypt, on every provider, so the
 * values here were made with that provider and are checked without it.
 */
public class Pkcs12PbeTest {

    /** The jasypt password: a stored keystore secret, as {@code GeoServerPBEPasswordEncoder} hands it over. */
    static final char[] PASSWORD = "usergroup-key-for-fips-tests-0123456789ab".toCharArray();

    static final String PLAINTEXT = "geoserver";

    /** {@code PBEWITHSHA256AND256BITAES-CBC-BC} on provider BC through jasypt 1.9.3, without the prefix. */
    static final String ENCRYPTED = "Xy22jv6ushfgyFFQpEaumKpbsw0zz4e9ia9EQRP4V/Y=";

    @Test
    public void testDecryptsWhatTheRegularProviderWrote() throws Exception {
        byte[] plain = Pkcs12Pbe.decrypt(PASSWORD, Base64.getDecoder().decode(ENCRYPTED), 256);
        assertEquals(PLAINTEXT, new String(plain, StandardCharsets.UTF_8));
    }

    @Test
    public void testWrongPasswordFails() {
        assertThrows(
                GeneralSecurityException.class,
                () -> Pkcs12Pbe.decrypt(
                        "wrong".toCharArray(), Base64.getDecoder().decode(ENCRYPTED), 256));
    }

    @Test
    public void testTooShortFails() {
        assertThrows(GeneralSecurityException.class, () -> Pkcs12Pbe.decrypt(PASSWORD, new byte[16], 256));
    }

    @Test
    public void testAlgorithmNames() {
        assertEquals(256, Pkcs12Pbe.keyBits("PBEWITHSHA256AND256BITAES-CBC-BC"));
        assertEquals(256, Pkcs12Pbe.keyBits("PBEWITHSHA256AND256BITAES-BC"));
        assertEquals(128, Pkcs12Pbe.keyBits("PBEWithSHA256And128BitAES-CBC-BC"));
        assertEquals(0, Pkcs12Pbe.keyBits("PBEWITHMD5ANDDES"));
        assertEquals(0, Pkcs12Pbe.keyBits("PBEWithHmacSHA256AndAES_128"));
        assertEquals(0, Pkcs12Pbe.keyBits(null));
    }

    @Test
    public void testBmpStringEncoding() {
        assertArrayEquals(new byte[] {0, 'a', 0, 'b', 0, 0}, Pkcs12Pbe.bmpString("ab".toCharArray()));
    }
}
