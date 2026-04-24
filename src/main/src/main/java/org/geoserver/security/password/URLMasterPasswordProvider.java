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

    /** FIPS-compatible algorithm for PBE encryption */
    static final String FIPS_PBE_ALGORITHM = "PBEWithHmacSHA256AndAES_128";

    /** Legacy algorithm (not FIPS-compliant) */
    static final String LEGACY_PBE_ALGORITHM = "PBEWithMD5AndDES";

    byte[] encode(char[] passwd) {

        if (!config.isEncrypting()) {
            return toBytes(passwd);
        }

        // encrypt the password
        StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
        // Use FIPS-compatible algorithm and generators
        encryptor.setAlgorithm(FIPS_PBE_ALGORITHM);
        encryptor.setSaltGenerator(new FipsRandomSaltGenerator());
        encryptor.setIvGenerator(new FipsRandomIvGenerator());

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

        // Try FIPS-compatible algorithm first
        try {
            return decodeWithAlgorithm(passwd, FIPS_PBE_ALGORITHM);
        } catch (Exception e) {
            // If FIPS algorithm failed and we're not in FIPS mode, try legacy algorithm
            if (!KeyStoreProviderImpl.isFipsMode()) {
                try {
                    // Explicitly use the legacy algorithm (Jasypt's default is also PBEWithMD5AndDES,
                    // but we specify it to avoid coupling to Jasypt internals)
                    byte[] decoded = decodeWithAlgorithm(passwd, LEGACY_PBE_ALGORITHM);
                    // Successfully decoded with legacy algorithm - migrate to FIPS algorithm
                    LOGGER.info(
                            "Master password was encrypted with legacy algorithm, migrating to FIPS-compatible algorithm");
                    migrateToFipsAlgorithm(decoded);
                    return decoded;
                } catch (Exception legacyEx) {
                    // Both algorithms failed
                    throw new RuntimeException(
                            "Failed to decrypt master password with both FIPS and legacy algorithms", e);
                }
            } else {
                // In FIPS mode and FIPS algorithm failed - probably legacy encrypted
                throw new RuntimeException(
                        "Failed to decrypt master password in FIPS mode. "
                                + "The password may have been encrypted with a legacy algorithm (PBEWithMD5AndDES). "
                                + "Please migrate your security directory on a non-FIPS system first, or delete the security directory to start fresh.",
                        e);
            }
        }
    }

    private byte[] decodeWithAlgorithm(byte[] passwd, String algorithm) {
        StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
        if (algorithm != null) {
            encryptor.setAlgorithm(algorithm);
            // FIPS algorithm also needs FIPS-compatible salt/IV generators for decryption
            if (FIPS_PBE_ALGORITHM.equals(algorithm)) {
                encryptor.setSaltGenerator(new FipsRandomSaltGenerator());
                encryptor.setIvGenerator(new FipsRandomIvGenerator());
            }
        }
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
        try {
            Resource configDir = getConfigDir();
            URL url = config.getURL();

            if (!"file".equalsIgnoreCase(url.getProtocol())) {
                LOGGER.info(
                        "Master password is stored at a non-file URL; "
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

            // Step 1: write new ciphertext to a temp file in the same directory (same filesystem)
            File tmpFile = File.createTempFile("passwd", ".tmp", parentDir);
            char[] passwd = toChars(copy);
            try {
                try (FileOutputStream fos = new FileOutputStream(tmpFile)) {
                    fos.write(encode(passwd));
                    fos.getFD().sync(); // fsync before rename
                }
            } finally {
                scramble(passwd);
            }

            // Step 2: create backup of the original file
            File backupFile = new File(targetFile.getPath() + ".backup");
            java.nio.file.Files.copy(
                    targetFile.toPath(),
                    backupFile.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            LOGGER.info("Created backup of master password file: " + backupFile.getPath());

            // Step 3: atomic rename of temp file over original (atomic on POSIX if same filesystem)
            java.nio.file.Files.move(
                    tmpFile.toPath(),
                    targetFile.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);

            LOGGER.info("Successfully migrated master password to FIPS-compatible encryption");
        } catch (java.nio.file.AtomicMoveNotSupportedException amEx) {
            LOGGER.warning(
                    "Atomic rename not supported on this filesystem. "
                            + "Master password migration skipped — re-save via admin UI to upgrade.");
        } catch (Exception e) {
            LOGGER.warning("Failed to migrate master password to FIPS algorithm: " + e.getMessage());
            // Don't throw — we successfully decoded, migration is best-effort
        } finally {
            java.util.Arrays.fill(copy, (byte) 0);
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
