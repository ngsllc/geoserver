/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
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
import javax.crypto.SecretKey;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.KeyStoreProvider;
import org.geoserver.security.KeyStoreProviderImpl;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Reversible password encoder built on AES-GCM, the {@code crypt3:} prefix. It uses only FIPS approved algorithms that
 * both the JDK providers and BC-FIPS offer, in approved-only mode included, so the same encoded values are readable on
 * every kind of installation, and by GeoServer upstream, whose encoder of the same name writes the same bytes.
 *
 * <p>The encoded form is {@code base64(}{@link AesGcmCipher#encrypt}{@code )}. Unlike the password based encoders, a
 * changed value, or one encrypted under another key, is detected: it fails to validate and cannot be decoded, instead
 * of decoding into meaningless characters.
 *
 * <p>The {@code char[]} methods wipe the plain text before returning, so it never reaches an object that cannot be
 * cleared. The {@code String} methods cannot do that, because {@link PasswordEncoder} takes and returns a
 * {@code String}: there the plain text stays on the heap until it is collected.
 */
public class GeoServerAesGcmPasswordEncoder extends AbstractGeoserverPasswordEncoder {

    private KeyStoreProvider keystoreProvider;
    private String keyAliasInKeyStore = KeyStoreProviderImpl.CONFIGPASSWORDKEY;

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

    public String getKeyAliasInKeyStore() {
        return keyAliasInKeyStore;
    }

    @Override
    public PasswordEncodingType getEncodingType() {
        return PasswordEncodingType.ENCRYPT;
    }

    @Override
    protected PasswordEncoder createStringEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                // a user may have no password at all; it has to stay missing rather than
                // become the encryption of an empty value, like the other reversible encoders do
                if (rawPassword == null) {
                    return null;
                }
                return encrypt(rawPassword.toString().getBytes(StandardCharsets.UTF_8));
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
            public String encodePassword(char[] rawPass, Object salt) {
                if (rawPass == null) {
                    return null;
                }
                byte[] bytes = toBytes(rawPass);
                try {
                    return encrypt(bytes);
                } finally {
                    scramble(bytes);
                }
            }

            @Override
            public boolean isPasswordValid(String encPass, char[] rawPass, Object salt) {
                if (rawPass == null || encPass == null) {
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
        };
    }

    /** Re-encodes an already encoded password, same contract as the other reversible encoders. */
    @Override
    public String encode(CharSequence rawPassword) {
        char[] plain = decodeToCharArray(rawPassword.toString());
        try {
            return createCharEncoder().encodePassword(plain, null);
        } finally {
            scramble(plain);
        }
    }

    @Override
    public String decode(String encPass) throws UnsupportedOperationException {
        byte[] decrypted = decryptToBytes(stripPrefix(encPass));
        try {
            return new String(decrypted, StandardCharsets.UTF_8);
        } finally {
            scramble(decrypted);
        }
    }

    @Override
    public char[] decodeToCharArray(String encPass) throws UnsupportedOperationException {
        byte[] decrypted = decryptToBytes(stripPrefix(encPass));
        try {
            return toChars(decrypted);
        } finally {
            scramble(decrypted);
        }
    }

    private String encrypt(byte[] plainText) {
        return Base64.getEncoder().encodeToString(AesGcmCipher.encrypt(key(), plainText));
    }

    /** Decrypts, or returns null when the value is not a valid encryption under this encoder's key. */
    private byte[] tryDecrypt(String encPass) {
        try {
            return decryptToBytes(encPass);
        } catch (RuntimeException e) {
            // a corrupt or foreign value is a failed match, not a server error; the cause matters to nobody but
            // an administrator chasing a broken data directory
            LOGGER.log(Level.FINE, "Encoded password does not decrypt under alias " + keyAliasInKeyStore, e);
            return null;
        }
    }

    private byte[] decryptToBytes(String encPass) {
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(encPass);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Encoded password is not valid Base64", e);
        }
        try {
            return AesGcmCipher.decrypt(key(), bytes);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(
                    "Encoded password cannot be decrypted with the key for alias " + keyAliasInKeyStore, e);
        }
    }

    /**
     * The keystore holds the derived key, not this class. Callers get a new encoder for every operation, so a key kept
     * here would be derived again each time, and that takes hundreds of milliseconds.
     *
     * <p>Never write to the keystore here. This runs while encoding, and nothing puts those calls in order, so two
     * threads could write two different keys and whatever the losing one encrypted could never be decrypted.
     */
    private SecretKey key() {
        try {
            return keystoreProvider.getDerivedKey(keyAliasInKeyStore, AesGcmCipher::deriveKey);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot derive the key for alias: " + keyAliasInKeyStore, e);
        }
    }
}
