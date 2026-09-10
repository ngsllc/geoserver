/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.geoserver.security.SecurityUtils.scramble;
import static org.geoserver.security.SecurityUtils.toBytes;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.geoserver.security.FipsRuntime;

/**
 * Makes a key from a password, then encrypts with it. Two steps, because no FIPS provider offers a {@code Cipher} that
 * takes a password directly. Every algorithm used here is FIPS approved and works on the JDK providers as well as on
 * BC-FIPS in approved-only mode.
 *
 * <p>The result is the initialization vector followed by the encrypted bytes, which already include the GCM
 * authentication tag. Parameters and layout are those of GeoServer upstream's {@code AesGcmCipher} (the {@code crypt3}
 * encoder), so values are readable across both.
 */
public final class AesGcmCipher {

    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";

    /** Length of the derivation salt, the 16 bytes NIST SP 800-132 section 5.1 asks for. */
    public static final int SALT_LENGTH = 16;

    /** The initialization vector length GCM is meant to use. */
    static final int IV_LENGTH = 12;

    private static final int TAG_LENGTH_BITS = 128;
    private static final int KEY_LENGTH_BITS = 256;

    /**
     * The count OWASP recommends for PBKDF2 with HMAC-SHA256. It takes about 100ms, and callers cache the key they get,
     * so it is not paid per encrypted value.
     */
    private static final int ITERATIONS = 600_000;

    /**
     * BC-FIPS refuses PBKDF2 from passwords under this many bits in approved-only mode (SP 800-132 strength floor).
     * GeoServer's secrets are random passwords of 32 characters and more, well above it.
     */
    public static final int MIN_PASSWORD_BITS = 112;

    private AesGcmCipher() {}

    /** Random bytes for salts and initialization vectors, from {@link FipsRuntime#secureRandom()}. */
    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        FipsRuntime.secureRandom().nextBytes(bytes);
        return bytes;
    }

    /**
     * Derives an AES key from a stored secret, salting it with a digest of the secret itself.
     *
     * <p>A salt has to differ per key, but it does not have to be secret or random. This is only meant for the random
     * keystore secrets GeoServer generates (40 characters, one per installation and user group service): they are
     * unique, so their digest is, and a random salt would have to be stored next to the very secret it salts. It must
     * never be used with a human chosen password, where a salt derived from the password lets one precomputed table
     * serve every installation.
     */
    public static SecretKey deriveKey(char[] secret) {
        return deriveKey(secret, salt(secret));
    }

    private static byte[] salt(char[] secret) {
        byte[] bytes = toBytes(secret);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            return Arrays.copyOf(digest, SALT_LENGTH);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not derive the encryption salt", e);
        } finally {
            scramble(bytes);
        }
    }

    /** Derives an AES key with a caller supplied salt, for the master password file, which keeps its own. */
    public static SecretKey deriveKey(char[] password, byte[] salt) {
        try {
            byte[] derived = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM)
                    .generateSecret(new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH_BITS))
                    .getEncoded();
            try {
                return new SecretKeySpec(derived, "AES");
            } finally {
                scramble(derived);
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not derive an encryption key", e);
        }
    }

    /** Encrypts with a fresh initialization vector, returned as a prefix of the result. */
    public static byte[] encrypt(SecretKey key, byte[] plainText) {
        byte[] iv = randomBytes(IV_LENGTH);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] cipherText = cipher.doFinal(plainText);
            byte[] result = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);
            return result;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not encrypt", e);
        }
    }

    /**
     * Reverses {@link #encrypt(SecretKey, byte[])}. GCM checks the data along with decrypting it, so a changed value,
     * or one encrypted under another key, is refused instead of turning into meaningless bytes.
     *
     * @throws AEADBadTagException when the value was modified or belongs to another key
     * @throws GeneralSecurityException when the value is malformed
     */
    public static byte[] decrypt(SecretKey key, byte[] ivAndCipherText) throws GeneralSecurityException {
        if (ivAndCipherText.length <= IV_LENGTH) {
            throw new GeneralSecurityException("Encrypted value is too short to hold an initialization vector");
        }
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, ivAndCipherText, 0, IV_LENGTH));
        return cipher.doFinal(ivAndCipherText, IV_LENGTH, ivAndCipherText.length - IV_LENGTH);
    }
}
