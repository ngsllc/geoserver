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
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.KeyStoreProvider;
import org.geoserver.security.KeyStoreProviderImpl;
import org.geotools.util.logging.Logging;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Password encoder using password based symmetric encryption ({@code crypt1} with MD5/DES, {@code crypt2} with the
 * PKCS#12 SHA-256/AES cipher of the regular BouncyCastle provider).
 *
 * <p>Neither cipher is FIPS approved, and no FIPS provider offers a password based cipher at all. Writing therefore
 * needs the cipher from a registered provider and fails with a message naming the encoder to use instead, while reading
 * works as far as it can: {@code crypt2} values are read with {@link Pkcs12Pbe}, which needs nothing but SHA-256 and
 * AES/CBC and so works on every provider, and {@code crypt1} values wherever the JVM still has MD5/DES. That is what
 * lets a data directory written by an earlier GeoServer move its passwords to {@code crypt3} on a FIPS installation,
 * see {@link GeoServerSecurityManager}.
 *
 * <p>The salt parameter is not used, this implementation computes a random salt as default.
 *
 * @author christian
 */
public class GeoServerPBEPasswordEncoder extends AbstractGeoserverPasswordEncoder {

    private static final Logger LOGGER = Logging.getLogger(GeoServerPBEPasswordEncoder.class);

    StandardPBEStringEncryptor stringEncrypter;
    StandardPBEByteEncryptor byteEncrypter;

    /**
     * The jasypt password, kept only for the PKCS#12 reader, which needs it for every value. Jasypt copies the password
     * into its own encryptors anyway, so keeping it here does not lengthen its stay on the heap. Encoders are prototype
     * beans, so an instance lives about as long as one operation.
     */
    private char[] pkcs12Password;

    private String providerName, algorithm;
    private String keyAliasInKeyStore = KeyStoreProviderImpl.CONFIGPASSWORDKEY;

    private KeyStoreProvider keystoreProvider;

    private Boolean cipherAvailable;

    @Override
    public void initialize(GeoServerSecurityManager securityManager) throws IOException {
        this.keystoreProvider = securityManager.getKeyStoreProvider();
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
        this.cipherAvailable = null;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
        this.cipherAvailable = null;
    }

    public String getKeyAliasInKeyStore() {
        return keyAliasInKeyStore;
    }

    /**
     * Whether a registered provider offers the cipher, which is what writing needs. Reading a {@code crypt2} value does
     * not, see {@link Pkcs12Pbe}; reading a {@code crypt1} value does.
     */
    public boolean isCipherAvailable() {
        if (cipherAvailable == null) {
            try {
                if (providerName != null && !providerName.isEmpty()) {
                    Cipher.getInstance(algorithm, providerName);
                } else {
                    Cipher.getInstance(algorithm);
                }
                cipherAvailable = true;
            } catch (GeneralSecurityException e) {
                LOGGER.log(Level.FINE, "Cipher " + algorithm + " is not available, " + getName() + " is read only", e);
                cipherAvailable = false;
            }
        }
        return cipherAvailable;
    }

    /** Whether values written by this encoder can be read on this installation. */
    public boolean canDecode() {
        return Pkcs12Pbe.keyBits(algorithm) > 0 || isCipherAvailable();
    }

    private void assertCipherAvailable() {
        if (!isCipherAvailable()) {
            throw new IllegalStateException("The '" + getName() + "' (" + getPrefix()
                    + ":) password encoder cannot encrypt: no registered crypto provider offers " + algorithm
                    + (providerName != null && !providerName.isEmpty() ? " from provider " + providerName : "")
                    + ". Values it wrote earlier are still read; new ones need an encoder the providers support,"
                    + " such as aesGcmPasswordEncoder (crypt3:).");
        }
    }

    @Override
    protected PasswordEncoder createStringEncoder() {
        initEncrypters();
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                if (rawPassword == null) {
                    return null;
                }
                assertCipherAvailable();
                return stringEncrypter.encrypt(rawPassword.toString());
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                if (rawPassword == null || encodedPassword == null) {
                    return false;
                }
                byte[] raw = rawPassword.toString().getBytes(StandardCharsets.UTF_8);
                try {
                    return matchesDecrypted(encodedPassword, raw);
                } finally {
                    scramble(raw);
                }
            }
        };
    }

    @Override
    protected CharArrayPasswordEncoder createCharEncoder() {
        initEncrypters();
        return new CharArrayPasswordEncoder() {
            @Override
            public boolean isPasswordValid(String encPass, char[] rawPass, Object salt) {
                if (encPass == null || rawPass == null) {
                    return false;
                }
                byte[] raw = toBytes(rawPass);
                try {
                    return matchesDecrypted(encPass, raw);
                } finally {
                    scramble(raw);
                }
            }

            @Override
            public String encodePassword(char[] rawPass, Object salt) {
                if (rawPass == null) {
                    return null;
                }
                assertCipherAvailable();
                byte[] bytes = toBytes(rawPass);
                try {
                    return new String(Base64.getEncoder().encode(byteEncrypter.encrypt(bytes)));
                } finally {
                    scramble(bytes);
                }
            }
        };
    }

    /**
     * Builds the jasypt encryptors, once. Nothing here asks a provider for the cipher: jasypt does that on the first
     * encryption, and the PKCS#12 reader never does.
     */
    private synchronized void initEncrypters() {
        if (byteEncrypter != null) {
            return;
        }
        byte[] password = lookupPasswordFromKeyStore();
        char[] chars = toChars(password);
        try {
            StandardPBEByteEncryptor bytes = new StandardPBEByteEncryptor();
            bytes.setPasswordCharArray(chars);
            bytes.setSaltGenerator(SecureRandomGenerator.INSTANCE);
            StandardPBEStringEncryptor strings = new StandardPBEStringEncryptor();
            strings.setPasswordCharArray(chars);
            strings.setSaltGenerator(SecureRandomGenerator.INSTANCE);
            if (getProviderName() != null && !getProviderName().isEmpty()) {
                bytes.setProviderName(getProviderName());
                strings.setProviderName(getProviderName());
            }
            bytes.setAlgorithm(getAlgorithm());
            strings.setAlgorithm(getAlgorithm());
            if (Pkcs12Pbe.keyBits(getAlgorithm()) > 0) {
                pkcs12Password = chars.clone();
            }
            stringEncrypter = strings;
            byteEncrypter = bytes;
        } finally {
            scramble(password);
            scramble(chars);
        }
    }

    /**
     * Whether the stored value decrypts to the given bytes. A value that does not decrypt, because it was damaged or
     * written under another key, is a mismatch and not an error, and the comparison takes the same time whichever byte
     * differs.
     */
    private boolean matchesDecrypted(String encPass, byte[] raw) {
        byte[] decrypted;
        try {
            decrypted = decryptBytes(encPass);
        } catch (GeneralSecurityException | RuntimeException e) {
            LOGGER.log(Level.FINE, "Encoded password does not decrypt under alias " + keyAliasInKeyStore, e);
            return false;
        }
        try {
            return MessageDigest.isEqual(decrypted, raw);
        } finally {
            scramble(decrypted);
        }
    }

    /**
     * Decrypts a Base64 value written by this encoder. PKCS#12 values go through {@link Pkcs12Pbe}, so no provider is
     * asked for a password based cipher; anything else goes through jasypt and whatever provider offers the cipher.
     */
    private byte[] decryptBytes(String encPass) throws GeneralSecurityException {
        initEncrypters();
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(encPass);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Encoded password is not valid Base64", e);
        }
        int keyBits = Pkcs12Pbe.keyBits(getAlgorithm());
        if (keyBits > 0) {
            return Pkcs12Pbe.decrypt(pkcs12Password, decoded, keyBits);
        }
        try {
            return byteEncrypter.decrypt(decoded);
        } catch (EncryptionOperationNotPossibleException | EncryptionInitializationException e) {
            throw new GeneralSecurityException("Encoded password cannot be decrypted with " + getAlgorithm(), e);
        }
    }

    byte[] lookupPasswordFromKeyStore() {
        try {
            if (!keystoreProvider.containsAlias(getKeyAliasInKeyStore())) {
                throw new RuntimeException("Keystore: "
                        + keystoreProvider.getResource().path()
                        + " does not"
                        + " contain alias: "
                        + getKeyAliasInKeyStore());
            }
            return keystoreProvider.getSecretKey(getKeyAliasInKeyStore()).getEncoded();
        } catch (IOException e) {
            throw new RuntimeException("Cannot find alias: "
                    + getKeyAliasInKeyStore()
                    + " in "
                    + keystoreProvider.getResource().path());
        }
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
