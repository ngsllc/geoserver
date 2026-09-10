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
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import org.junit.Test;

public class AesGcmCipherTest {

    /**
     * Produced by GeoServer upstream's {@code AesGcmCipher} at the merge of geoserver/geoserver#9855: the key it
     * derives from this secret, and one value it encrypted under that key. Reading both proves the {@code crypt3}
     * format is the same on both sides.
     */
    static final String UPSTREAM_SECRET =
            "geoserver-interop-secret-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    static final String UPSTREAM_DERIVED_KEY = "h6L4YSALQh97vHYXU9BRyS12t8joPG8Drx484wU5264=";
    static final String UPSTREAM_CIPHERTEXT = "fVh4ZNn38PLUmKytl3fkh2w2Qt38riBpmNeo+XARsJnKp0yNVrMwZWIkj6SO";
    static final String UPSTREAM_PLAINTEXT = "interop-plaintext";

    @Test
    public void testKeyDerivationMatchesUpstream() {
        SecretKey key = AesGcmCipher.deriveKey(UPSTREAM_SECRET.toCharArray());
        assertEquals(UPSTREAM_DERIVED_KEY, Base64.getEncoder().encodeToString(key.getEncoded()));
    }

    @Test
    public void testDecryptsUpstreamValue() throws Exception {
        SecretKey key = AesGcmCipher.deriveKey(UPSTREAM_SECRET.toCharArray());
        byte[] plain = AesGcmCipher.decrypt(key, Base64.getDecoder().decode(UPSTREAM_CIPHERTEXT));
        assertEquals(UPSTREAM_PLAINTEXT, new String(plain, StandardCharsets.UTF_8));
    }

    @Test
    public void testRoundTripWithFreshIv() throws Exception {
        SecretKey key = AesGcmCipher.deriveKey("a-forty-character-random-keystore-secret".toCharArray());
        byte[] plain = "the same value twice".getBytes(StandardCharsets.UTF_8);
        byte[] first = AesGcmCipher.encrypt(key, plain);
        byte[] second = AesGcmCipher.encrypt(key, plain);
        assertFalse("every encryption draws a new IV", Arrays.equals(first, second));
        assertArrayEquals(plain, AesGcmCipher.decrypt(key, first));
        assertArrayEquals(plain, AesGcmCipher.decrypt(key, second));
    }

    @Test
    public void testTamperingIsDetected() {
        SecretKey key = AesGcmCipher.deriveKey("a-forty-character-random-keystore-secret".toCharArray());
        byte[] encrypted = AesGcmCipher.encrypt(key, "secret".getBytes(StandardCharsets.UTF_8));
        encrypted[encrypted.length - 1] ^= 1;
        assertThrows(AEADBadTagException.class, () -> AesGcmCipher.decrypt(key, encrypted));
    }

    @Test
    public void testWrongKeyIsDetected() {
        SecretKey key = AesGcmCipher.deriveKey("a-forty-character-random-keystore-secret".toCharArray());
        SecretKey other = AesGcmCipher.deriveKey("another-forty-character-keystore-secret!".toCharArray());
        byte[] encrypted = AesGcmCipher.encrypt(key, "secret".getBytes(StandardCharsets.UTF_8));
        assertThrows(AEADBadTagException.class, () -> AesGcmCipher.decrypt(other, encrypted));
    }

    @Test
    public void testTooShortIsRefused() {
        SecretKey key = AesGcmCipher.deriveKey("a-forty-character-random-keystore-secret".toCharArray());
        assertThrows(Exception.class, () -> AesGcmCipher.decrypt(key, new byte[AesGcmCipher.IV_LENGTH]));
    }
}
