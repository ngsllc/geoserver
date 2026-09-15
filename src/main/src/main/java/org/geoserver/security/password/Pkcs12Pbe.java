/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Reads values written with the PKCS#12 password based cipher the {@code crypt2} encoder uses,
 * {@code PBEWITHSHA256AND256BITAES-CBC-BC} from the regular BouncyCastle provider.
 *
 * <p>That cipher is not FIPS approved and no FIPS provider offers it, so an installation that moved to the FIPS
 * provider could not read its own stored passwords, and a data directory could not be migrated at all. The scheme
 * itself only needs SHA-256 and AES/CBC, which every provider has, so it is implemented here directly after RFC 7292
 * appendix B. Nothing is ever written in this format: the reader exists so that stored values can be moved to
 * {@code crypt3}.
 *
 * <p>Layout, as jasypt produces it for this cipher: a 16 byte salt, then the ciphertext. The cipher derives its own
 * initialization vector from the password and salt, so none is stored. Key derivation uses jasypt's default 1000
 * iterations and the PKCS#12 BMPString encoding of the password.
 */
public final class Pkcs12Pbe {

    /** Salt length jasypt uses for this cipher: its 8 byte default widened to the AES block size. */
    static final int SALT_LENGTH = 16;

    /** Block size of AES, and the length of the derived initialization vector. */
    static final int BLOCK_LENGTH = 16;

    /** jasypt's default key obtention iterations. */
    static final int ITERATIONS = 1000;

    private static final String ALGORITHM_PREFIX = "PBEWITHSHA256AND";

    private static final String ALGORITHM_INFIX = "BITAES";

    private static final int ID_KEY = 1;
    private static final int ID_IV = 2;

    private Pkcs12Pbe() {}

    /**
     * Decrypts a jasypt PKCS#12 SHA-256/AES-CBC value.
     *
     * @param password the jasypt password
     * @param message salt followed by ciphertext
     * @param keyBits AES key size the writer used, see {@link #keyBits(String)}
     * @throws GeneralSecurityException when the value cannot be decrypted, padding included
     */
    public static byte[] decrypt(char[] password, byte[] message, int keyBits) throws GeneralSecurityException {
        if (message.length <= SALT_LENGTH) {
            throw new GeneralSecurityException("Encrypted value too short to hold a salt and ciphertext");
        }
        byte[] salt = Arrays.copyOfRange(message, 0, SALT_LENGTH);
        byte[] bmp = bmpString(password);
        byte[] key = derive(bmp, salt, ID_KEY, keyBits / 8);
        byte[] iv = derive(bmp, salt, ID_IV, BLOCK_LENGTH);
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return cipher.doFinal(message, SALT_LENGTH, message.length - SALT_LENGTH);
        } finally {
            Arrays.fill(bmp, (byte) 0);
            Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * Whether a jasypt algorithm name is one of the PKCS#12 SHA-256/AES-CBC ciphers this class reads, returning the key
     * size in bits, or 0 when it is not.
     */
    public static int keyBits(String algorithm) {
        if (algorithm == null) {
            return 0;
        }
        String upper = algorithm.toUpperCase();
        if (!upper.startsWith(ALGORITHM_PREFIX) || !upper.contains(ALGORITHM_INFIX)) {
            return 0;
        }
        String bits = upper.substring(ALGORITHM_PREFIX.length(), upper.indexOf(ALGORITHM_INFIX));
        try {
            int size = Integer.parseInt(bits);
            return size == 128 || size == 192 || size == 256 ? size : 0;
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /** PKCS#12 password encoding: big endian UTF-16 with a two byte terminator. */
    static byte[] bmpString(char[] password) {
        byte[] bytes = new byte[(password.length + 1) * 2];
        for (int i = 0; i < password.length; i++) {
            bytes[2 * i] = (byte) (password[i] >>> 8);
            bytes[2 * i + 1] = (byte) password[i];
        }
        return bytes;
    }

    /** RFC 7292 appendix B.2 with SHA-256: u = 32, v = 64. */
    static byte[] derive(byte[] password, byte[] salt, int id, int length) throws NoSuchAlgorithmException {
        int u = 32, v = 64;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] d = new byte[v];
        Arrays.fill(d, (byte) id);
        byte[] s = repeat(salt, v);
        byte[] p = repeat(password, v);
        byte[] i = new byte[s.length + p.length];
        System.arraycopy(s, 0, i, 0, s.length);
        System.arraycopy(p, 0, i, s.length, p.length);
        int blocks = (length + u - 1) / u;
        byte[] out = new byte[blocks * u];
        for (int block = 1; block <= blocks; block++) {
            digest.reset();
            digest.update(d);
            digest.update(i);
            byte[] a = digest.digest();
            for (int round = 1; round < ITERATIONS; round++) {
                a = digest.digest(a);
            }
            System.arraycopy(a, 0, out, (block - 1) * u, u);
            if (block < blocks) {
                byte[] b = repeat(a, v);
                for (int j = 0; j < i.length / v; j++) {
                    int carry = 1;
                    for (int k = v - 1; k >= 0; k--) {
                        int sum = (i[j * v + k] & 0xff) + (b[k] & 0xff) + carry;
                        i[j * v + k] = (byte) sum;
                        carry = sum >>> 8;
                    }
                }
            }
        }
        return Arrays.copyOf(out, length);
    }

    private static byte[] repeat(byte[] source, int v) {
        if (source.length == 0) {
            return new byte[0];
        }
        int length = v * ((source.length + v - 1) / v);
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = source[i % source.length];
        }
        return result;
    }
}
