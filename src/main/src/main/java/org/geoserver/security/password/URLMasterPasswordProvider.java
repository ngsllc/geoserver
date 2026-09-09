/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.geoserver.security.SecurityUtils.scramble;
import static org.geoserver.security.SecurityUtils.toBytes;
import static org.geoserver.security.SecurityUtils.toChars;
import static org.geoserver.security.password.URLMasterPasswordProviderException.URL_LOCATION_NOT_READABLE;
import static org.geoserver.security.password.URLMasterPasswordProviderException.URL_REQUIRED;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.geoserver.config.util.XStreamPersister;
import org.geoserver.platform.resource.Resource;
import org.geoserver.platform.resource.Resource.Type;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerSecurityProvider;
import org.geoserver.security.KeyStoreProviderImpl;
import org.geoserver.security.MasterPasswordProvider;
import org.geoserver.security.SecurityUtils;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.validation.SecurityConfigException;
import org.geoserver.security.validation.SecurityConfigValidator;
import org.geotools.util.URLs;
import org.geotools.util.logging.Logging;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;

/**
 * Master password provider that retrieves and optionally stores the master password from a url.
 *
 * @author Justin Deoliveira, OpenGeo
 */
public final class URLMasterPasswordProvider extends MasterPasswordProvider {

    private static final Logger LOGGER = Logging.getLogger(URLMasterPasswordProvider.class);

    /** base encryption key */
    static final char[] BASE = {
        'U', 'n', '6', 'd', 'I', 'l', 'X', 'T', 'Q', 'c', 'L', ')', '$', '#', 'q', 'J', 'U',
        'l', 'X', 'Q', 'U', '!', 'n', 'n', 'p', '%', 'U', 'r', '5', 'U', 'u', '3', '5', 'H',
        '`', 'x', 'P', 'F', 'r', 'X'
    };

    /** permutation indices */
    static final int[] PERM = {
        32, 19, 30, 11, 34, 26, 3, 21, 9, 37, 38, 13, 23, 2, 18, 4, 20, 1, 29, 17, 0, 31, 14, 36, 12, 24, 15, 35, 16,
        39, 25, 5, 10, 8, 7, 6, 33, 27, 28, 22
    };

    URLMasterPasswordProviderConfig config;

    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);
        this.config = (URLMasterPasswordProviderConfig) config;
    }

    @Override
    protected char[] doGetMasterPassword() throws Exception {
        try {
            try (InputStream in = input(config.getURL(), getConfigDir())) {
                return toChars(decode(IOUtils.toByteArray(in)));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void doSetMasterPassword(char[] passwd) throws Exception {
        try (OutputStream out = output(config.getURL(), getConfigDir())) {
            out.write(encode(passwd));
        }
    }

    Resource getConfigDir() throws IOException {
        return getSecurityManager().masterPasswordProvider().get(getName());
    }

    /**
     * Algorithm used to encrypt the master password file. Provided by the BouncyCastle FIPS provider only, so every
     * encryptor built for it registers the provider first, see {@link KeyStoreProviderImpl#FIPS_PBE_ALGORITHM}.
     */
    static final String FIPS_PBE_ALGORITHM = KeyStoreProviderImpl.FIPS_PBE_ALGORITHM;

    /**
     * FIPS-compatible algorithm used by earlier FIPS builds (PBES2 with HMAC-SHA256 and AES-128, provided by SunJCE).
     * Kept so master password files written by those builds can still be read; they are re-encrypted with
     * {@link #FIPS_PBE_ALGORITHM} on first use.
     */
    static final String PREVIOUS_FIPS_PBE_ALGORITHM = "PBEWithHmacSHA256AndAES_128";

    /** Legacy algorithm (not FIPS-compliant), the Jasypt default used before FIPS support was added */
    static final String LEGACY_PBE_ALGORITHM = "PBEWithMD5AndDES";

    /**
     * Algorithms that may have been used to write an existing master password file, in the order in which they are
     * tried when reading. Anything decoded with an algorithm other than {@link #FIPS_PBE_ALGORITHM} is migrated.
     */
    static final List<String> KNOWN_PBE_ALGORITHMS =
            List.of(FIPS_PBE_ALGORITHM, PREVIOUS_FIPS_PBE_ALGORITHM, LEGACY_PBE_ALGORITHM);

    /**
     * Builds a Jasypt encryptor for one of the {@link #KNOWN_PBE_ALGORITHMS}. The current FIPS algorithm is pinned to
     * the BCFIPS provider, which is registered on demand so that this works regardless of whether a keystore or
     * password encoder has been initialized first, in both FIPS and non-FIPS mode.
     */
    static StandardPBEByteEncryptor newEncryptor(String algorithm) {
        StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
        encryptor.setAlgorithm(algorithm);
        if (FIPS_PBE_ALGORITHM.equals(algorithm)) {
            if (KeyStoreProviderImpl.ensureBcFipsProviderRegistered()) {
                encryptor.setProviderName(KeyStoreProviderImpl.BCFIPS_PROVIDER);
            }
        }
        if (!LEGACY_PBE_ALGORITHM.equals(algorithm)) {
            // AES based algorithms need an IV; use FIPS-compatible generators instead of Jasypt's SHA1PRNG defaults
            encryptor.setSaltGenerator(new FipsRandomSaltGenerator());
            encryptor.setIvGenerator(new FipsRandomIvGenerator());
        }
        return encryptor;
    }

    byte[] encode(char[] passwd) {

        if (!config.isEncrypting()) {
            return toBytes(passwd);
        }

        return encodeWithAlgorithm(passwd, FIPS_PBE_ALGORITHM);
    }

    byte[] encodeWithAlgorithm(char[] passwd, String algorithm) {
        StandardPBEByteEncryptor encryptor = newEncryptor(algorithm);
        char[] key = key();
        try {
            encryptor.setPasswordCharArray(key);
            return Base64.encodeBase64(encryptor.encrypt(toBytes(passwd)));
        } finally {
            scramble(key);
        }
    }

    byte[] decode(byte[] passwd) {
        if (!config.isEncrypting()) {
            return passwd;
        }

        Exception failure = null;
        for (String algorithm : KNOWN_PBE_ALGORITHMS) {
            byte[] decoded;
            try {
                decoded = decodeWithAlgorithm(passwd, algorithm);
            } catch (Exception e) {
                if (failure == null) {
                    failure = e;
                } else {
                    failure.addSuppressed(e);
                }
                continue;
            }
            if (!FIPS_PBE_ALGORITHM.equals(algorithm)) {
                // Readable, but not with the current algorithm: re-encrypt so the next read succeeds directly and
                // the file can be read once legacy algorithms are blocked by an OS level FIPS policy
                LOGGER.info("Master password was encrypted with " + algorithm + ", migrating to " + FIPS_PBE_ALGORITHM);
                migrateToFipsAlgorithm(decoded);
            }
            return decoded;
        }

        String message = "Failed to decrypt master password with " + KNOWN_PBE_ALGORITHMS + ". ";
        if (KeyStoreProviderImpl.isFipsMode()) {
            message += "The password may have been encrypted with the legacy PBEWithMD5AndDES algorithm, which is "
                    + "blocked on FIPS enabled operating systems. Start GeoServer once with FIPS_MODE=true on a host "
                    + "where OS level FIPS is disabled so the file is migrated, or delete the security directory to "
                    + "start fresh.";
        } else {
            message += "The file may be corrupt or encrypted with a different key.";
        }
        throw new RuntimeException(message, failure);
    }

    private byte[] decodeWithAlgorithm(byte[] passwd, String algorithm) {
        StandardPBEByteEncryptor encryptor = newEncryptor(algorithm);
        char[] key = key();
        try {
            encryptor.setPasswordCharArray(key);
            return encryptor.decrypt(Base64.decodeBase64(passwd));
        } finally {
            scramble(key);
        }
    }

    private void migrateToFipsAlgorithm(byte[] decryptedPassword) {
        // Work on a copy so the caller's array is not zeroed
        byte[] copy = java.util.Arrays.copyOf(decryptedPassword, decryptedPassword.length);
        File tmpFile = null;
        try {
            Resource configDir = getConfigDir();
            URL url = config.getURL();

            if (!"file".equalsIgnoreCase(url.getProtocol())) {
                LOGGER.info("Master password is stored at a non-file URL; "
                        + "automatic migration is not supported. "
                        + "Re-save the master password via the admin UI to upgrade to FIPS-compatible encryption.");
                return;
            }

            File originalFile = URLs.urlToFile(url);

            // Resolve the target file and its parent directory
            File targetFile;
            if (!originalFile.isAbsolute()) {
                // Relative path — resolve within config dir
                Resource res = configDir.get(originalFile.getPath());
                targetFile = res.file(); // materializes the Resource to a java.io.File
            } else {
                targetFile = originalFile;
            }
            File parentDir = targetFile.getParentFile();

            // Step 1: encrypt with the current algorithm; done before touching the file system so that an
            // unavailable algorithm leaves no temp file behind
            byte[] encoded;
            char[] passwd = toChars(copy);
            try {
                encoded = encode(passwd);
            } finally {
                scramble(passwd);
            }

            // Step 2: write new ciphertext to a temp file in the same directory (same filesystem)
            tmpFile = File.createTempFile("passwd", ".tmp", parentDir);
            try (FileOutputStream fos = new FileOutputStream(tmpFile)) {
                fos.write(encoded);
                fos.getFD().sync(); // fsync before rename
            }

            // Step 3: create backup of the original file
            File backupFile = new File(targetFile.getPath() + ".backup");
            java.nio.file.Files.copy(
                    targetFile.toPath(), backupFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            LOGGER.info("Created backup of master password file: " + backupFile.getPath());

            // Step 4: atomic rename of temp file over original (atomic on POSIX if same filesystem)
            java.nio.file.Files.move(
                    tmpFile.toPath(),
                    targetFile.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            tmpFile = null;

            LOGGER.info("Successfully migrated master password to " + FIPS_PBE_ALGORITHM);
        } catch (java.nio.file.AtomicMoveNotSupportedException amEx) {
            LOGGER.warning("Atomic rename not supported on this filesystem. "
                    + "Master password migration skipped — re-save via admin UI to upgrade.");
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to migrate master password to " + FIPS_PBE_ALGORITHM + ": " + e, e);
            // Don't throw — we successfully decoded, migration is best-effort
        } finally {
            java.util.Arrays.fill(copy, (byte) 0);
            if (tmpFile != null && tmpFile.exists() && !tmpFile.delete()) {
                LOGGER.warning("Could not delete temporary master password file " + tmpFile.getPath());
            }
        }
    }

    char[] key() {
        // generate the key
        return SecurityUtils.permute(BASE, 32, PERM);
    }

    static OutputStream output(URL url, Resource configDir) throws IOException {
        // check for file url
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            File f = URLs.urlToFile(url);
            if (!f.isAbsolute()) {
                // make relative to config dir
                return configDir.get(f.getPath()).out();
            } else {
                return new FileOutputStream(f);
            }
        } else {
            URLConnection cx = url.openConnection();
            cx.setDoOutput(true);
            return cx.getOutputStream();
        }
    }

    static InputStream input(URL url, Resource configDir) throws IOException {
        // check for a file url
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            File f = URLs.urlToFile(url);
            // check if the file is relative
            if (!f.isAbsolute()) {
                // make it relative to the config directory for this password provider
                Resource res = configDir.get(f.getPath());
                if (res.getType() != Type.RESOURCE) { // file must already exist.
                    throw new FileNotFoundException();
                }
                return res.in();
            } else {
                return new FileInputStream(f);
            }
        } else {
            return url.openStream();
        }
    }

    public static class URLMasterPasswordProviderValidator extends SecurityConfigValidator {

        public URLMasterPasswordProviderValidator(GeoServerSecurityManager securityManager) {
            super(securityManager);
        }

        @Override
        public void validate(MasterPasswordProviderConfig config) throws SecurityConfigException {
            super.validate(config);

            URLMasterPasswordProviderConfig urlConfig = (URLMasterPasswordProviderConfig) config;
            URL url = urlConfig.getURL();

            if (url == null) {
                throw new URLMasterPasswordProviderException(URL_REQUIRED);
            }

            if (config.isReadOnly()) {
                // read-only, assure we can read from url
                try {
                    try (InputStream in =
                            input(url, manager.masterPasswordProvider().get(config.getName()))) {
                        in.read();
                    }
                } catch (IOException ex) {
                    throw new URLMasterPasswordProviderException(URL_LOCATION_NOT_READABLE, url);
                }
            }
        }
    }

    public static class SecurityProvider extends GeoServerSecurityProvider {
        @Override
        public void configure(XStreamPersister xp) {
            super.configure(xp);
            xp.getXStream().alias("urlProvider", URLMasterPasswordProviderConfig.class);
        }

        @Override
        public Class<? extends MasterPasswordProvider> getMasterPasswordProviderClass() {
            return URLMasterPasswordProvider.class;
        }

        @Override
        public MasterPasswordProvider createMasterPasswordProvider(MasterPasswordProviderConfig config)
                throws IOException {
            return new URLMasterPasswordProvider();
        }

        @Override
        public SecurityConfigValidator createConfigurationValidator(GeoServerSecurityManager securityManager) {
            return new URLMasterPasswordProviderValidator(securityManager);
        }
    }
}
