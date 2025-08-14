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
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.KeyStoreProvider;
import org.geoserver.security.KeyStoreProviderImpl;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Password Encoder using symmetric encryption
 *
 * <p>The salt parameter is not used, this implementation computes a random salt as default.
 *
 * <p>{@link #isPasswordValid(String, String, Object)} {@link #encodePassword(String, Object)}
 *
 * @author christian
 */
public class GeoServerPBEPasswordEncoder extends AbstractGeoserverPasswordEncoder {

    /** Algorithms that are NOT FIPS-compliant and cannot be used when FIPS mode is enabled */
    private static final java.util.Set<String> NON_FIPS_ALGORITHMS =
            java.util.Set.of("PBEWITHMD5ANDDES", "PBEWITHMD5ANDTRIPLEDES", "PBEWITHSHA1ANDDES", "PBEWITHSHA1ANDDESEDE");

    StandardPBEStringEncryptor stringEncrypter;
    StandardPBEByteEncryptor byteEncrypter;

    private String providerName, algorithm;
    private String keyAliasInKeyStore = KeyStoreProviderImpl.CONFIGPASSWORDKEY;

    private KeyStoreProvider keystoreProvider;

    @Override
    public void initialize(GeoServerSecurityManager securityManager) throws IOException {
        this.keystoreProvider = securityManager.getKeyStoreProvider();
        if (KeyStoreProviderImpl.isFipsMode()
                && algorithm != null
                && NON_FIPS_ALGORITHMS.contains(algorithm.toUpperCase())) {
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

    @Override
    protected PasswordEncoder createStringEncoder() {
        byte[] password = lookupPasswordFromKeyStore();

        String passwordString = Base64.getEncoder().encodeToString(password);
        char[] chars = passwordString.toCharArray();
        try {
            stringEncrypter = new StandardPBEStringEncryptor();
            stringEncrypter.setPasswordCharArray(chars);
            // Use FIPS-compatible generators instead of Jasypt's defaults which use SHA1PRNG
            stringEncrypter.setSaltGenerator(new FipsRandomSaltGenerator());
            stringEncrypter.setIvGenerator(new FipsRandomIvGenerator());

            ensureProviderAvailableIfRequested();
            if (getProviderName() != null && !getProviderName().isEmpty())
                stringEncrypter.setProviderName(getProviderName());
            stringEncrypter.setAlgorithm(getAlgorithm());

            JasyptPBEPasswordEncoderWrapper encoder = new JasyptPBEPasswordEncoderWrapper();
            encoder.setPbeStringEncryptor(stringEncrypter);

            return encoder;
        } finally {
            scramble(password);
            scramble(chars);
        }
    }

    @Override
    protected CharArrayPasswordEncoder createCharEncoder() {
        byte[] password = lookupPasswordFromKeyStore();
        String passwordString = Base64.getEncoder().encodeToString(password);
        char[] chars = passwordString.toCharArray();

        byteEncrypter = new StandardPBEByteEncryptor();
        byteEncrypter.setPasswordCharArray(chars);
        // Use FIPS-compatible generators instead of Jasypt's defaults which use SHA1PRNG
        byteEncrypter.setSaltGenerator(new FipsRandomSaltGenerator());
        byteEncrypter.setIvGenerator(new FipsRandomIvGenerator());
        ensureProviderAvailableIfRequested();
        if (getProviderName() != null && !getProviderName().isEmpty()) byteEncrypter.setProviderName(getProviderName());
        byteEncrypter.setAlgorithm(getAlgorithm());

        return new CharArrayPasswordEncoder() {
            @Override
            public boolean isPasswordValid(String encPass, char[] rawPass, Object salt) {
                byte[] decoded = Base64.getDecoder().decode(encPass.getBytes());
                byte[] decrypted = byteEncrypter.decrypt(decoded);

                char[] chars = toChars(decrypted);
                try {
                    return Arrays.equals(chars, rawPass);
                } finally {
                    scramble(decrypted);
                    scramble(chars);
                }
            }

            @Override
            public String encodePassword(char[] rawPass, Object salt) {
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
     * Ensures the requested JCE provider (e.g., "BCFIPS") is available; attempts lazy registration to preserve backward
     * compatibility with configurations that specify a provider.
     */
    private void ensureProviderAvailableIfRequested() {
        String requested = getProviderName();
        if (requested == null || requested.isEmpty()) return;
        Provider existing = Security.getProvider(requested);
        if (existing != null) return;
        try {
            if ("BCFIPS".equals(requested)) {
                Class<?> providerClass = Class.forName("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider");
                Security.addProvider(
                        (Provider) providerClass.getDeclaredConstructor().newInstance());
            }
            // Note: Regular BC provider is not shipped with GeoServer; only BC-FIPS is available
        } catch (ReflectiveOperationException | SecurityException ignored) {
            // If provider cannot be registered, jasypt will try default provider; acceptable fallback
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
        if (stringEncrypter == null) {
            // not initialized
            getStringEncoder();
        }

        return stringEncrypter.decrypt(removePrefix(encPass));
    }

    @Override
    public char[] decodeToCharArray(String encPass) throws UnsupportedOperationException {
        if (byteEncrypter == null) {
            // not initialized
            getCharEncoder();
        }

        byte[] decoded = Base64.getDecoder().decode(removePrefix(encPass).getBytes());
        byte[] bytes = byteEncrypter.decrypt(decoded);
        try {
            return toChars(bytes);
        } finally {
            scramble(bytes);
        }
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return createCharEncoder().encodePassword(decodeToCharArray(rawPassword.toString()), null);
    }
}
