/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import org.junit.Test;

public class Pkcs12PbeTest {

    /**
     * Written by jasypt with {@code PBEWITHSHA256AND256BITAES-BC} on the BouncyCastle FIPS provider (bc-fips 2.1.2,
     * default mode), as the earlier FIPS builds did: with an IV generator (crypt2 under a key created with FIPS
     * support, the master password file) and without one (crypt2 under a legacy key, and everything GeoServer upstream
     * writes with stock BouncyCastle).
     */
    static final char[] PASSWORD = "fixed-vector-password-40-chars-long-XXXXX".toCharArray();

    static final String PLAINTEXT = "crypt2-plaintext";
    static final String WITH_IV =
            "W7JTcwnfQ0itKOLv3Cmifbl+5sOTBiDuwYagtS5ruQ2KNPWB+MncYlonBt37CGEf3R3/YS0gaLKjujHvZE0sdw==";
    static final String WITHOUT_IV = "TtPKrzjlk7sRL7nnfW4WbRooLQ5utImZeIZ7BUNOLda9+0jlrAuPBokc2obqGmWv";

    @Test
    public void testDecryptsValueWrittenWithIvGenerator() throws Exception {
        byte[] plain = Pkcs12Pbe.decrypt(PASSWORD, Base64.getDecoder().decode(WITH_IV), 256, true);
        assertEquals(PLAINTEXT, new String(plain, StandardCharsets.UTF_8));
    }

    @Test
    public void testDecryptsValueWrittenWithoutIvGenerator() throws Exception {
        byte[] plain = Pkcs12Pbe.decrypt(PASSWORD, Base64.getDecoder().decode(WITHOUT_IV), 256, false);
        assertEquals(PLAINTEXT, new String(plain, StandardCharsets.UTF_8));
    }

    @Test
    public void testWrongPasswordFails() {
        assertThrows(
                GeneralSecurityException.class,
                () -> Pkcs12Pbe.decrypt(
                        "wrong".toCharArray(), Base64.getDecoder().decode(WITH_IV), 256, true));
    }

    /**
     * CBC without authentication cannot tell a wrong layout from a right one: the 16 ignored bytes decrypt as a first
     * block of garbage and the padding on the last block still checks out. This is why the layout is a property of the
     * key ({@code GeoServerPBEPasswordEncoder.KeyMaterial}) and never probed, and one of the reasons {@code crypt3}
     * uses GCM.
     */
    @Test
    public void testWrongLayoutYieldsGarbageNotAnError() throws Exception {
        byte[] plain = Pkcs12Pbe.decrypt(PASSWORD, Base64.getDecoder().decode(WITH_IV), 256, false);
        assertFalse(PLAINTEXT.equals(new String(plain, StandardCharsets.UTF_8)));
    }

    @Test
    public void testTooShortFails() {
        assertThrows(GeneralSecurityException.class, () -> Pkcs12Pbe.decrypt(PASSWORD, new byte[20], 256, true));
    }

    @Test
    public void testAlgorithmNames() {
        assertEquals(256, Pkcs12Pbe.keyBits("PBEWITHSHA256AND256BITAES-BC"));
        assertEquals(256, Pkcs12Pbe.keyBits("PBEWITHSHA256AND256BITAES-CBC-BC"));
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
