/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.geoserver.security.SecurityUtils.scramble;
import static org.geoserver.security.SecurityUtils.toBytes;
import static org.geoserver.security.SecurityUtils.toChars;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.Base64;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.geoserver.security.FipsRuntime;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.KeyStoreProvider;
import org.geoserver.security.KeyStoreProviderImpl;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.iv.NoIvGenerator;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Password encoder using password based symmetric encryption ({@code crypt1:} with MD5/DES, {@code crypt2:} with
 * PKCS#12 SHA-256/AES).
 *
 * <p>None of these ciphers is FIPS approved. In FIPS mode this encoder therefore only <em>reads</em>, so that a data
 * directory written by an earlier version can be migrated to the AES-GCM {@link GeoServerAesGcmPasswordEncoder}
 * ({@code crypt3:}); writing throws. The PKCS#12 values are read with {@link Pkcs12Pbe}, which needs nothing but
 * SHA-256 and AES/CBC and so works in BouncyCastle's approved-only mode; the MD5/DES values can only be read where the
 * JVM still offers that cipher, which an operating system in FIPS mode does not.
 *
 * <p>The salt parameter is not used, this implementation computes a random salt as default.
 *
 * @author christian
 */
public class GeoServerPBEPasswordEncoder extends AbstractGeoserverPasswordEncoder {

    private static final Logger LOGGER = Logger.getLogger(GeoServerPBEPasswordEncoder.class.getName());

    /** Algorithms that are NOT FIPS-compliant and that a FIPS enabled operating system blocks entirely */
    private static final Set<String> NON_FIPS_ALGORITHMS =
            Set.of("PBEWITHMD5ANDDES", "PBEWITHMD5ANDTRIPLEDES", "PBEWITHSHA1ANDDES", "PBEWITHSHA1ANDDESEDE");

    StandardPBEStringEncryptor stringEncrypter;
    StandardPBEByteEncryptor byteEncrypter;

    private String providerName, algorithm;
    private String keyAliasInKeyStore = KeyStoreProviderImpl.CONFIGPASSWORDKEY;

    private KeyStoreProvider keystoreProvider;

    /**
     * Read once, on first use, and kept for the life of this (prototype scoped) encoder. Jasypt copies the password
     * into its own encryptor anyway, so scrambling it here would not shorten how long it stays on the heap, and the
     * PKCS#12 reader needs the characters for every value it decrypts.
     */
    private volatile KeyMaterial keyMaterial;

    @Override
    public void initialize(GeoServerSecurityManager securityManager) throws IOException {
        this.keystoreProvider = securityManager.getKeyStoreProvider();
        if (FipsRuntime.isFipsMode() && !isAvailableInFipsMode()) {
            throw new IOException("Algorithm '" + algorithm + "' not available in FIPS mode");
        }
    }

    @Override
    public void initializeFor(GeoServerUserGroupService service) throws IOException {
        if (!keystoreProvider.hasUserGroupKey(service.getName())) {
            throw new IOException("No key alias: "
                    + keystoreProvider.aliasForGroupService(service.getName())
                    + " in key store: "
                    + keystoreProvider.getResource().path());
        }

        keyAliasInKeyStore = keystoreProvider.aliasForGroupService(service.getName());
    }

    public String getProviderName() {
        return providerName;
    }

    public void setProviderName(String providerName) {
        this.providerName = providerName;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getKeyAliasInKeyStore() {
        return keyAliasInKeyStore;
    }

    /**
     * Whether values written with this encoder can be read in FIPS mode. The PKCS#12 ciphers always can, through
     * {@link Pkcs12Pbe}; the MD5/DES ciphers only where the JVM still offers them, so that a data directory created by
     * an earlier GeoServer can be migrated on a host whose operating system is not (yet) in FIPS mode.
     *
     * <p>Writing is never available in FIPS mode, see {@link #assertWritable()}.
     */
    public boolean isAvailableInFipsMode() {
        if (algorithm == null || Pkcs12Pbe.keyBits(algorithm) > 0) {
            return true;
        }
        if (!NON_FIPS_ALGORITHMS.contains(algorithm.toUpperCase())) {
            return true;
        }
        try {
            Cipher.getInstance(algorithm);
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** In FIPS mode this encoder is read only: the AES-GCM encoder writes. */
    private void assertWritable() {
        if (FipsRuntime.isFipsMode()) {
            throw new IllegalStateException("The '" + getName() + "' (" + getPrefix() + ":) password encoder uses "
                    + algorithm + ", which is not FIPS approved; in FIPS mode passwords are written with the "
                    + "aesGcmPasswordEncoder (crypt3:) encoder");
        }
    }

    @Override
    protected PasswordEncoder createStringEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                if (rawPassword == null) {
                    return null;
                }
                assertWritable();
                return stringEncrypter().encrypt(rawPassword.toString());
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                if (rawPassword == null || encodedPassword == null) {
                    return false;
                }
                byte[] decrypted = tryDecrypt(encodedPassword);
                if (decrypted == null) {
                    return false;
                }
                byte[] raw = rawPassword.toString().getBytes(StandardCharsets.UTF_8);
                try {
                    return MessageDigest.isEqual(decrypted, raw);
                } finally {
                    scramble(decrypted);
                    scramble(raw);
                }
            }
        };
    }

    @Override
    protected CharArrayPasswordEncoder createCharEncoder() {
        return new CharArrayPasswordEncoder() {
            @Override
            public boolean isPasswordValid(String encPass, char[] rawPass, Object salt) {
                if (encPass == null || rawPass == null) {
                    return false;
                }
                byte[] decrypted = tryDecrypt(encPass);
                if (decrypted == null) {
                    return false;
                }
                byte[] raw = toBytes(rawPass);
                try {
                    return MessageDigest.isEqual(decrypted, raw);
                } finally {
                    scramble(decrypted);
                    scramble(raw);
                }
            }

            @Override
            public String encodePassword(char[] rawPass, Object salt) {
                if (rawPass == null) {
                    return null;
                }
                assertWritable();
                byte[] bytes = toBytes(rawPass);
                try {
                    return new String(Base64.getEncoder().encode(byteEncrypter().encrypt(bytes)));
                } finally {
                    scramble(bytes);
                }
            }
        };
    }

    /**
     * Decrypts a Base64 value written by this encoder. PKCS#12 values go through {@link Pkcs12Pbe}, so no password
     * based cipher is ever asked of a provider; anything else (MD5/DES) goes through jasypt and the JDK.
     */
    private byte[] decryptBytes(String encPass) throws GeneralSecurityException {
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(encPass);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Encoded password is not valid Base64", e);
        }
        int pkcs12Bits = Pkcs12Pbe.keyBits(getAlgorithm());
        if (pkcs12Bits > 0) {
            KeyMaterial key = keyMaterial();
            // keys created with FIPS support wrote an IV generator's bytes into the value, legacy keys did not
            return Pkcs12Pbe.decrypt(key.password, bytes, pkcs12Bits, !key.legacy);
        }
        try {
            return byteEncrypter().decrypt(bytes);
        } catch (EncryptionOperationNotPossibleException e) {
            throw new GeneralSecurityException("Encoded password cannot be decrypted", e);
        }
    }

    /** Decrypts, or returns null when the value is not a valid encryption under this encoder's key. */
    private byte[] tryDecrypt(String encPass) {
        try {
            return decryptBytes(encPass);
        } catch (GeneralSecurityException | RuntimeException e) {
            LOGGER.log(Level.FINE, "Encoded password does not decrypt under alias " + keyAliasInKeyStore, e);
            return null;
        }
    }

    /** The jasypt string encryptor, built on first use so that FIPS mode never asks the provider for the cipher. */
    private synchronized StandardPBEStringEncryptor stringEncrypter() {
        if (stringEncrypter == null) {
            KeyMaterial key = keyMaterial();
            StandardPBEStringEncryptor encrypter = new StandardPBEStringEncryptor();
            encrypter.setPasswordCharArray(key.password);
            // FIPS-compatible generators instead of Jasypt's defaults which use SHA1PRNG
            encrypter.setSaltGenerator(new FipsRandomSaltGenerator());
            encrypter.setIvGenerator(key.legacy ? new NoIvGenerator() : new FipsRandomIvGenerator());
            ensureProviderAvailableIfRequested();
            if (getProviderName() != null && !getProviderName().isEmpty()) {
                encrypter.setProviderName(getProviderName());
            }
            encrypter.setAlgorithm(getAlgorithm());
            stringEncrypter = encrypter;
        }
        return stringEncrypter;
    }

    /** The jasypt byte encryptor, built on first use so that FIPS mode never asks the provider for the cipher. */
    private synchronized StandardPBEByteEncryptor byteEncrypter() {
        if (byteEncrypter == null) {
            KeyMaterial key = keyMaterial();
            StandardPBEByteEncryptor encrypter = new StandardPBEByteEncryptor();
            encrypter.setPasswordCharArray(key.password);
            // FIPS-compatible generators instead of Jasypt's defaults which use SHA1PRNG
            encrypter.setSaltGenerator(new FipsRandomSaltGenerator());
            encrypter.setIvGenerator(key.legacy ? new NoIvGenerator() : new FipsRandomIvGenerator());
            ensureProviderAvailableIfRequested();
            if (getProviderName() != null && !getProviderName().isEmpty()) {
                encrypter.setProviderName(getProviderName());
            }
            encrypter.setAlgorithm(getAlgorithm());
            byteEncrypter = encrypter;
        }
        return byteEncrypter;
    }

    /**
     * The Jasypt password derived from the keystore key backing this encoder, and the on-disk format that goes with it.
     *
     * <p>Two generations of keys exist. Keys stored as the raw bytes of a random printable password (all keys created
     * by GeoServer upstream and, since the AES-GCM encoder, by this fork) use those characters as the Jasypt password
     * and the PKCS#12 derived IV, which are the Jasypt defaults. Keys created by earlier FIPS builds of this fork are
     * 256 bit AES keys derived with SHA-256; values encrypted with them use the Base64 form of the key and carry an IV
     * generator's bytes. The format is a property of the key rather than of the individual value, so every value under
     * one key is written and read the same way and data directories coming from earlier GeoServer versions keep
     * working.
     */
    static final class KeyMaterial {
        final char[] password;
        final boolean legacy;

        KeyMaterial(char[] password, boolean legacy) {
            this.password = password;
            this.legacy = legacy;
        }
    }

    /** A key derived by an earlier FIPS build of this fork is an AES key; anything else is a stored random password. */
    static boolean isLegacyKey(SecretKey key) {
        return !KeyStoreProviderImpl.DEFAULT_SECRET_KEY_ALGORITHM.equalsIgnoreCase(key.getAlgorithm());
    }

    private KeyMaterial keyMaterial() {
        KeyMaterial current = keyMaterial;
        if (current == null) {
            synchronized (this) {
                current = keyMaterial;
                if (current == null) {
                    current = lookupKeyMaterial();
                    keyMaterial = current;
                }
            }
        }
        return current;
    }

    KeyMaterial lookupKeyMaterial() {
        SecretKey key;
        try {
            if (!keystoreProvider.containsAlias(getKeyAliasInKeyStore())) {
                throw new RuntimeException("Keystore: "
                        + keystoreProvider.getResource().path()
                        + " does not"
                        + " contain alias: "
                        + getKeyAliasInKeyStore());
            }
            key = keystoreProvider.getSecretKey(getKeyAliasInKeyStore());
        } catch (IOException e) {
            throw new RuntimeException(
                    "Cannot read key " + getKeyAliasInKeyStore() + " from "
                            + keystoreProvider.getResource().path() + ": " + e.getMessage(),
                    e);
        }
        if (key == null) {
            throw new RuntimeException("Cannot find alias: " + getKeyAliasInKeyStore() + " in "
                    + keystoreProvider.getResource().path());
        }
        byte[] encoded = key.getEncoded();
        try {
            boolean legacy = isLegacyKey(key);
            char[] password = legacy
                    ? toChars(encoded)
                    : Base64.getEncoder().encodeToString(encoded).toCharArray();
            return new KeyMaterial(password, legacy);
        } finally {
            scramble(encoded);
        }
    }

    /**
     * Ensures the requested JCE provider (e.g., "BCFIPS") is available; attempts lazy registration to preserve backward
     * compatibility with configurations that specify a provider.
     */
    private void ensureProviderAvailableIfRequested() {
        String requested = getProviderName();
        if (requested == null || requested.isEmpty()) return;
        Provider existing = Security.getProvider(requested);
        if (existing != null) return;
        // Note: Regular BC provider is not shipped with GeoServer; only BC-FIPS is available
        if (KeyStoreProviderImpl.BCFIPS_PROVIDER.equals(requested)
                && KeyStoreProviderImpl.ensureBcFipsProviderRegistered()) {
            return;
        }
        LOGGER.log(Level.FINE, "Provider '" + requested + "' not available, falling back to default JCA providers");
    }

    @Override
    public PasswordEncodingType getEncodingType() {
        return PasswordEncodingType.ENCRYPT;
    }

    @Override
    public String decode(String encPass) throws UnsupportedOperationException {
        byte[] decrypted = decodeBytes(encPass);
        try {
            return new String(decrypted, StandardCharsets.UTF_8);
        } finally {
            scramble(decrypted);
        }
    }

    @Override
    public char[] decodeToCharArray(String encPass) throws UnsupportedOperationException {
        byte[] decrypted = decodeBytes(encPass);
        try {
            return toChars(decrypted);
        } finally {
            scramble(decrypted);
        }
    }

    private byte[] decodeBytes(String encPass) {
        try {
            return decryptBytes(removePrefix(encPass));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(
                    "Encoded password cannot be decrypted with the key for alias " + keyAliasInKeyStore, e);
        }
    }

    @Override
    public String encode(CharSequence rawPassword) {
        char[] plain = decodeToCharArray(rawPassword.toString());
        try {
            return createCharEncoder().encodePassword(plain, null);
        } finally {
            scramble(plain);
        }
    }
}
