/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security;

import static org.geoserver.security.SecurityUtils.toBytes;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.geoserver.platform.resource.Resource;
import org.geoserver.platform.resource.Resource.Type;
import org.geoserver.security.password.RandomPasswordProvider;
import org.geotools.util.logging.Logging;
import org.springframework.beans.factory.BeanNameAware;

/**
 * Class for GeoServer specific key management
 *
 * <p><strong>requires a master password</strong> from {@link MasterPasswordProvider}
 *
 * <p>The type of the keystore is automatically determined based on FIPS mode. When FIPS_MODE environment variable is
 * set to "true", BCFKS keystore format is used. Otherwise, JCEKS format is used. The keystore can be used/modified with
 * java tools like "keytool" from the command line.
 *
 * @author christian
 */
public class KeyStoreProviderImpl implements BeanNameAware, KeyStoreProvider {

    public static final String DEFAULT_BEAN_NAME = "DefaultKeyStoreProvider";
    public static final String FIPS_MODE_ENV_VAR = "FIPS_MODE";
    public static final String JCEKS_KEYSTORE_TYPE = "JCEKS";
    public static final String BCFKS_KEYSTORE_TYPE = "BCFKS";
    public static final String BCFIPS_PROVIDER = "BCFIPS";
    public static final String DEFAULT_SECRET_KEY_ALGORITHM = "AES";

    // Dynamic file names based on keystore type
    private String defaultFileName;
    private String preparedFileName;

    // Cache for keystore type to avoid repeated environment lookups
    private String cachedKeyStoreType;

    public static final String CONFIGPASSWORDKEY = "config:password:key";
    public static final String URLPARAMKEY = "url:param:key";
    public static final String USERGROUP_PREFIX = "ug:";
    public static final String USERGROUP_POSTFIX = ":key";

    protected static Logger LOGGER = Logging.getLogger("org.geoserver.security");
    protected String name;
    protected volatile Resource keyStoreResource;
    protected volatile KeyStore ks;

    GeoServerSecurityManager securityManager;

    public KeyStoreProviderImpl() {
        this.cachedKeyStoreType = getKeyStoreType();
        initializeFileNames();
    }

    /** Gets the keystore type based on FIPS mode: BCFKS for FIPS, JCEKS otherwise */
    public static String getKeyStoreType() {
        // BCFKS is the BouncyCastle FIPS-compliant keystore
        // JCEKS is not available in FIPS mode (uses non-FIPS DES/3DES)
        // Note: BCFKS can store secret keys but only with FIPS-approved algorithms (e.g., AES)
        if (isFipsMode()) {
            return BCFKS_KEYSTORE_TYPE;
        } else {
            return JCEKS_KEYSTORE_TYPE;
        }
    }

    /** Detects if FIPS mode is enabled. OS-level FIPS cannot be overridden. */
    public static boolean isFipsMode() {
        // First check if OS-level FIPS is enabled - this cannot be overridden
        if (isOsFipsEnabled()) {
            // Log warning if user tried to disable FIPS on a FIPS system
            String propValue = System.getProperty(FIPS_MODE_ENV_VAR);
            String envValue = System.getenv(FIPS_MODE_ENV_VAR);
            if ("false".equalsIgnoreCase(propValue) || "false".equalsIgnoreCase(envValue)) {
                LOGGER.warning("FIPS_MODE=false ignored: OS-level FIPS is enabled and cannot be overridden");
            }
            return true;
        }

        // OS doesn't have FIPS, check if user wants to enable FIPS mode for testing
        // Check system property first to allow tests and runtime overrides
        String propValue = System.getProperty(FIPS_MODE_ENV_VAR);
        if (propValue != null && !propValue.trim().isEmpty()) {
            return "true".equalsIgnoreCase(propValue.trim());
        }
        // Check environment variable as fallback
        String envValue = System.getenv(FIPS_MODE_ENV_VAR);
        if (envValue != null && !envValue.trim().isEmpty()) {
            return "true".equalsIgnoreCase(envValue.trim());
        }
        return false;
    }

    /**
     * Checks if an algorithm name is FIPS-approved for secret key storage. BCFKS keystore rejects keys with non-FIPS
     * algorithm names like PBEWithMD5AndDES.
     */
    private static boolean isFipsApprovedAlgorithm(String algorithm) {
        if (algorithm == null) return false;
        String upper = algorithm.toUpperCase();
        // FIPS-approved symmetric algorithms
        return upper.equals("AES")
                || upper.startsWith("AES/")
                || upper.equals("DESEDE")
                || upper.equals("3DES")
                || upper.equals("HMACSHA256")
                || upper.equals("HMACSHA384")
                || upper.equals("HMACSHA512")
                || (upper.startsWith("PBEWITHHMACSHA") && upper.contains("AES"));
    }

    /**
     * Detects if OS-level FIPS mode is enabled. Checks Linux /proc/sys/crypto/fips_enabled and Java security providers.
     */
    private static boolean isOsFipsEnabled() {
        // Check Linux FIPS mode via /proc/sys/crypto/fips_enabled
        try {
            Path fipsFile = Paths.get("/proc/sys/crypto/fips_enabled");
            if (Files.exists(fipsFile)) {
                String content = Files.readString(fipsFile).trim();
                if ("1".equals(content)) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Ignore - file may not exist on non-Linux systems
        }

        // Check for OS-level FIPS security providers (e.g., SunPKCS11-NSS-FIPS).
        // Deliberately exclude application-level providers like "BCFIPS" — those are
        // added by GeoServer itself and do not indicate OS-level FIPS enforcement.
        for (java.security.Provider provider : Security.getProviders()) {
            String name = provider.getName();
            if (name == null) continue;
            // SunPKCS11-NSS-FIPS = Red Hat / Fedora FIPS mode via NSS
            if (name.contains("NSS-FIPS") || name.contains("SunPKCS11-FIPS")) {
                return true;
            }
        }

        return false;
    }

    /** Gets the appropriate provider for the keystore type */
    public static String getKeyStoreProvider() {
        String keystoreType = getKeyStoreType();
        return getKeyStoreProviderForType(keystoreType);
    }

    /** Gets the appropriate provider for a specific keystore type */
    public static String getKeyStoreProviderForType(String keystoreType) {
        if (BCFKS_KEYSTORE_TYPE.equals(keystoreType)) {
            // BCFKS requires BouncyCastle FIPS provider (will be registered if not available)
            return BCFIPS_PROVIDER;
        }
        return null; // Use default provider for other types
    }

    /**
     * Infer keystore type from the file path extension, falling back to the provided default type. Recognized
     * extensions: .jceks, .jks, .bcfks
     */
    private static final java.util.Map<String, String> EXTENSION_TO_TYPE_MAP =
            java.util.Map.of(".jceks", "JCEKS", ".jks", "JKS", ".bcfks", "BCFKS");

    private static String inferTypeFromPathOrDefault(String filePath, String defaultType) {
        if (filePath == null) return defaultType;
        String lower = filePath.toLowerCase();
        for (java.util.Map.Entry<String, String> entry : EXTENSION_TO_TYPE_MAP.entrySet()) {
            if (lower.endsWith(entry.getKey())) {
                return entry.getValue();
            }
        }
        return defaultType;
    }

    /**
     * Detect actual keystore type by examining file content (magic bytes). This is more reliable than relying on
     * filename extensions.
     */
    private String detectKeystoreType(Resource resource) throws IOException {
        if (resource.getType() == Type.UNDEFINED) {
            return null; // File doesn't exist
        }

        try (InputStream is = resource.in()) {
            // Read first 4 bytes to identify format
            byte[] header = new byte[4];
            int bytesRead = is.read(header);
            if (bytesRead < 4) {
                return null; // File too small
            }

            // JCEKS/JKS format starts with 0xCECECECE (magic number)
            if (header[0] == (byte) 0xCE
                    && header[1] == (byte) 0xCE
                    && header[2] == (byte) 0xCE
                    && header[3] == (byte) 0xCE) {
                // Could be JKS or JCEKS, but both use same structure
                // For migration purposes, we'll assume JCEKS (more common for GeoServer)
                return "JCEKS";
            }

            // BCFKS format starts with ASN.1 SEQUENCE tag: 0x30 0x82
            // PKCS12 also starts with 0x30 but typically uses 0x30 0x82 followed by
            // version info. We try BCFKS first; if it fails to load, the caller
            // will fall back to filename-based detection.
            if (header[0] == (byte) 0x30 && header[1] == (byte) 0x82) {
                // Distinguish BCFKS from PKCS12 by attempting a probe load
                return probeBcfksOrPkcs12(resource);
            }

            // Unknown format
            LOGGER.log(
                    Level.WARNING,
                    "Unknown keystore format, first bytes: "
                            + String.format("%02X %02X %02X %02X", header[0], header[1], header[2], header[3]));
            return null;
        }
    }

    /**
     * Probe whether an ASN.1-format keystore is BCFKS or PKCS12 by attempting to load it. Falls
     * back to filename-based detection if neither loads successfully.
     */
    private String probeBcfksOrPkcs12(Resource resource) {
        // Try BCFKS first (more specific to this codebase)
        try (InputStream in = resource.in()) {
            KeyStore ks = KeyStore.getInstance(BCFKS_KEYSTORE_TYPE, BCFIPS_PROVIDER);
            ks.load(in, null);
            return BCFKS_KEYSTORE_TYPE;
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Probe for BCFKS failed, trying PKCS12: " + e.getMessage());
        }
        // Try PKCS12
        try (InputStream in = resource.in()) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(in, null);
            return "PKCS12";
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Probe for PKCS12 failed: " + e.getMessage());
        }
        // Default to BCFKS (original behavior) if probes fail — caller handles load errors
        LOGGER.log(Level.WARNING, "Could not determine ASN.1 keystore type by probing, defaulting to BCFKS");
        return BCFKS_KEYSTORE_TYPE;
    }

    private void ensureProviderAvailable(String keystoreType, String provider) {
        if (!BCFKS_KEYSTORE_TYPE.equals(keystoreType)) {
            return;
        }
        if (provider != null && java.security.Security.getProvider(provider) == null) {
            try {
                if (BCFIPS_PROVIDER.equals(provider)) {
                    // Load BouncyCastle FIPS provider
                    try {
                        Class<?> providerClass =
                                Class.forName("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider");
                        java.security.Provider bcProvider = (java.security.Provider)
                                providerClass.getDeclaredConstructor().newInstance();
                        java.security.Security.addProvider(bcProvider);
                        LOGGER.info("Successfully registered BouncyCastle FIPS provider");

                        // Validate that the provider supports required algorithms
                        validateProviderSupport(bcProvider);
                    } catch (ClassNotFoundException e) {
                        LOGGER.log(
                                Level.SEVERE,
                                "BouncyCastle FIPS provider not available in classpath. "
                                        + "Ensure bc-fips dependency is included.",
                                e);
                        throw new RuntimeException("BouncyCastle FIPS provider required but not available", e);
                    } catch (Exception e) {
                        LOGGER.log(Level.SEVERE, "Failed to register BouncyCastle FIPS provider: " + e.getMessage(), e);
                        throw new RuntimeException("Failed to register BouncyCastle FIPS provider", e);
                    }
                }
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Failed to register BouncyCastle provider: " + e.getMessage(), e);
                throw new RuntimeException("Failed to register BouncyCastle provider", e);
            }
        }
    }

    /**
     * Validates that the provider supports required algorithms for FIPS operations. This ensures the provider is
     * properly configured before attempting keystore operations.
     */
    private void validateProviderSupport(java.security.Provider provider) throws Exception {
        // Verify the provider supports BCFKS keystore type
        try {
            KeyStore testKs = KeyStore.getInstance(BCFKS_KEYSTORE_TYPE, provider);
            testKs.load(null, null);
            LOGGER.log(Level.FINE, "Provider " + provider.getName() + " successfully supports BCFKS keystore");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Provider does not support BCFKS keystore: " + e.getMessage(), e);
            throw new RuntimeException("Provider validation failed: BCFKS keystore not supported", e);
        }

        // Verify the provider supports required algorithms
        try {
            java.security.MessageDigest.getInstance("SHA-256", provider);
            LOGGER.log(Level.FINE, "Provider " + provider.getName() + " supports SHA-256");
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Provider may not support SHA-256: " + e.getMessage());
        }
    }

    protected KeyStore createKeyStore(String keystoreType, String provider)
            throws KeyStoreException, NoSuchProviderException {
        ensureProviderAvailable(keystoreType, provider);
        if (provider != null) {
            return java.security.KeyStore.getInstance(keystoreType, provider);
        }
        return java.security.KeyStore.getInstance(keystoreType);
    }

    /**
     * Copy all key entries from one keystore to another using the provided password for both.
     *
     * <p>Only key entries are copied; trusted cert-only entries are not currently used by GeoServer's symmetric secret
     * keys and are therefore ignored for simplicity.
     *
     * <p>When copying to JCEKS, keys are normalized to SecretKeySpec to avoid Java serialization filter issues.
     */
    private void copyKeyEntries(KeyStore source, KeyStore target, char[] password) throws Exception {
        java.util.Enumeration<String> aliases = source.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (source.isKeyEntry(alias)) {
                LOGGER.log(Level.FINE, "Processing key alias: '" + alias + "'");
                Key key = source.getKey(alias, password);

                // Always normalize SecretKeys to SecretKeySpec for cross-keystore compatibility
                // JCEKS needs this to avoid serialization filter issues
                // BCFKS needs this because it can't store PBE-wrapped keys
                if (key instanceof SecretKey) {
                    byte[] encoded = key.getEncoded();
                    if (encoded != null) {
                        // For BCFKS in FIPS mode, we must use a FIPS-approved algorithm name
                        // BCFKS rejects keys with PBE algorithm names like "PBEWithMD5AndDES"
                        String targetAlgorithm = key.getAlgorithm();
                        if ("BCFKS".equals(target.getType()) && !isFipsApprovedAlgorithm(targetAlgorithm)) {
                            targetAlgorithm = DEFAULT_SECRET_KEY_ALGORITHM; // Use AES
                        }
                        key = new SecretKeySpec(encoded, targetAlgorithm);
                        LOGGER.log(Level.FINE, "Normalized key '" + alias + "' to SecretKeySpec with algorithm " + targetAlgorithm);
                    } else {
                        LOGGER.log(
                                Level.SEVERE,
                                "Cannot normalize key '" + alias + "' - getEncoded() returned null.");
                        throw new Exception("Cannot migrate key '" + alias + "' - key encoding is not available");
                    }
                }

                java.security.cert.Certificate[] chain = source.getCertificateChain(alias);
                target.setKeyEntry(alias, key, password, chain);
                LOGGER.log(Level.FINE, "Copied key during migration: " + alias);
            }
        }
    }

    /** Initialize file names based on the keystore type */
    private void initializeFileNames() {
        String keystoreType = this.cachedKeyStoreType;
        String extension = keystoreType.toLowerCase();
        this.defaultFileName = "geoserver." + extension;
        this.preparedFileName = "geoserver." + extension + ".new";
    }

    /** Gets the cached keystore type for this instance */
    public String getCachedKeyStoreType() {
        return this.cachedKeyStoreType;
    }

    /** Refreshes the cached keystore type and updates file names if the environment has changed */
    public void refreshKeyStoreType() {
        String newType = getKeyStoreType();
        if (!newType.equals(this.cachedKeyStoreType)) {
            this.cachedKeyStoreType = newType;
            initializeFileNames();
        }
    }

    /** Gets the default file name for the current keystore type */
    public String getDefaultFileName() {
        return defaultFileName;
    }

    /** Gets the prepared file name for the current keystore type */
    public String getPreparedFileName() {
        return preparedFileName;
    }

    @Override
    public void setBeanName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    @Override
    public void setSecurityManager(GeoServerSecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    public GeoServerSecurityManager getSecurityManager() {
        return securityManager;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getKeyStoreProvderFile()
     */
    @Override
    public Resource getResource() {
        Resource result = keyStoreResource;
        if (result == null) {
            synchronized (this) {
                result = keyStoreResource;
                if (result == null) {
                    Resource baseDir = securityManager.security();

                    // First check for any existing keystore files (for migration support)
                    Resource legacyJceks = baseDir.get("geoserver.jceks");
                    Resource legacyJks = baseDir.get("geoserver.jks");
                    Resource legacyBcfks = baseDir.get("geoserver.bcfks");

                    Resource candidate = null;

                    // 1. Prefer the file matching the current active mode
                    if (BCFKS_KEYSTORE_TYPE.equals(cachedKeyStoreType) && legacyBcfks.getType() != Type.UNDEFINED) {
                        candidate = legacyBcfks;
                    } else if (JCEKS_KEYSTORE_TYPE.equals(cachedKeyStoreType) && legacyJceks.getType() != Type.UNDEFINED) {
                        candidate = legacyJceks;
                    }

                    // 2. If not found, check for other existing files (migration sources)
                    if (candidate == null) {
                        if (legacyJceks.getType() != Type.UNDEFINED) {
                            candidate = legacyJceks;
                        } else if (legacyJks.getType() != Type.UNDEFINED) {
                            candidate = legacyJks;
                        } else if (legacyBcfks.getType() != Type.UNDEFINED) {
                            candidate = legacyBcfks;
                        }
                    }

                    // 3. If no existing file found, use the default filename for current mode
                    if (candidate == null) {
                        candidate = baseDir.get(getDefaultFileName());
                    }

                    keyStoreResource = candidate;
                    result = candidate;
                }
            }
        }
        return result;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#reloadKeyStore()
     */
    @Override
    public synchronized void reloadKeyStore() throws IOException {
        ks = null;
        keyStoreResource = null; // Clear cached resource to allow re-evaluation
        cachedKeyStoreType = getKeyStoreType(); // Re-evaluate FIPS mode
        initializeFileNames(); // Update expected filenames
        assertActivatedKeyStore();
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getKey(java.lang.String)
     */
    @Override
    public Key getKey(String alias) throws IOException {
        assertActivatedKeyStore();
        try {
            char[] passwd = securityManager.getMasterPassword();
            try {
                return ks.getKey(alias, passwd);
            } finally {
                securityManager.disposePassword(passwd);
            }
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getConfigPasswordKey()
     */
    @Override
    public byte[] getConfigPasswordKey() throws IOException {
        SecretKey key = getSecretKey(CONFIGPASSWORDKEY);
        if (key == null) return null;
        return key.getEncoded();
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#hasConfigPasswordKey()
     */
    @Override
    public boolean hasConfigPasswordKey() throws IOException {
        return containsAlias(CONFIGPASSWORDKEY);
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#containsAlias(java.lang.String)
     */
    @Override
    public boolean containsAlias(String alias) throws IOException {
        assertActivatedKeyStore();
        try {
            return ks.containsAlias(alias);
        } catch (KeyStoreException e) {
            throw new IOException(e);
        }
    }
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getUserGRoupKey(java.lang.String)
     */
    @Override
    public byte[] getUserGroupKey(String serviceName) throws IOException {
        SecretKey key = getSecretKey(aliasForGroupService(serviceName));
        if (key == null) return null;
        return key.getEncoded();
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#hasUserGRoupKey(java.lang.String)
     */
    @Override
    public boolean hasUserGroupKey(String serviceName) throws IOException {
        return containsAlias(aliasForGroupService(serviceName));
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getSecretKey(java.lang.String)
     */
    @Override
    public SecretKey getSecretKey(String name) throws IOException {
        Key key = getKey(name);
        if (key == null) return null;
        if ((key instanceof SecretKey) == false) throw new IOException("Invalid key type for: " + name);
        return (SecretKey) key;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getPublicKey(java.lang.String)
     */
    @Override
    public PublicKey getPublicKey(String name) throws IOException {
        Key key = getKey(name);
        if (key == null) return null;
        if ((key instanceof PublicKey) == false) throw new IOException("Invalid key type for: " + name);
        return (PublicKey) key;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getPrivateKey(java.lang.String)
     */
    @Override
    public PrivateKey getPrivateKey(String name) throws IOException {
        Key key = getKey(name);
        if (key == null) return null;
        if ((key instanceof PrivateKey) == false) throw new IOException("Invalid key type for: " + name);
        return (PrivateKey) key;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#aliasForGroupService(java.lang.String)
     */
    @Override
    public String aliasForGroupService(String serviceName) {
        StringBuffer buff = new StringBuffer(USERGROUP_PREFIX);
        buff.append(serviceName);
        buff.append(USERGROUP_POSTFIX);
        return buff.toString();
    }

    /**
     * Opens or creates a {@link KeyStore} using the file {@link #getDefaultFileName()}
     *
     * <p>Throws an exception for an invalid master key
     */
    protected synchronized void assertActivatedKeyStore() throws IOException {
        if (ks != null) return;

        char[] passwd = securityManager.getMasterPassword();
        try {
            String keystoreType = this.cachedKeyStoreType;
            String resourcePath = getResource().path();

            // First, try to detect actual format from file content (more reliable than filename)
            String effectiveType = detectKeystoreType(getResource());
            if (effectiveType == null) {
                // Fall back to filename-based detection
                effectiveType = inferTypeFromPathOrDefault(resourcePath, keystoreType);
            }

            LOGGER.log(
                    Level.FINE,
                    "KeyStore path: " + resourcePath + ", keystoreType: " + keystoreType + ", effectiveType: "
                            + effectiveType);

            if (getResource().getType() == Type.UNDEFINED) { // create an empty one
                String provider = getKeyStoreProviderForType(keystoreType);
                ks = createKeyStore(keystoreType, provider);
                ks.load(null, passwd);
                addInitialKeys();
                try (OutputStream fos = getResource().out()) {
                    ks.store(fos, passwd);
                }
            } else if (!effectiveType.equals(keystoreType)) {
                // Type mismatch, migrate keys from old keystore to new keystore type
                LOGGER.log(
                        Level.INFO,
                        "Keystore type mismatch (expected: " + keystoreType + ", found: " + effectiveType
                                + "), migrating keystore from " + effectiveType + " to " + keystoreType);

                // Check if we're trying to migrate from JCEKS when OS FIPS is enabled
                if ("JCEKS".equals(effectiveType) && isOsFipsEnabled()) {
                    throw new IOException("Cannot migrate JCEKS keystore when OS-level FIPS mode is enabled.\n\n"
                            + "JCEKS keystores are not available in OS FIPS mode.\n\n"
                            + "To migrate your keystore:\n"
                            + "1. Temporarily disable OS FIPS mode\n"
                            + "2. Set the FIPS_MODE=true environment variable for GeoServer\n"
                            + "3. Restart GeoServer — it will auto-migrate JCEKS to BCFKS\n"
                            + "4. Remove the FIPS_MODE variable\n"
                            + "5. Re-enable OS FIPS mode and restart\n\n"
                            + "Alternative: Delete " + getResource().path() + " to start fresh with BCFKS.");
                }

                // Create backup before migration
                Resource backupResource = null;
                Resource oldResource = getResource();
                if (oldResource.getType() != Type.UNDEFINED) {
                    backupResource = securityManager.security().get(oldResource.name() + ".backup");
                    try {
                        java.nio.file.Files.copy(
                                oldResource.file().toPath(),
                                backupResource.file().toPath(),
                                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                        LOGGER.log(Level.FINE, "Created backup: " + backupResource.name());
                    } catch (Exception e) {
                        LOGGER.log(Level.WARNING, "Failed to create backup before migration: " + e.getMessage(), e);
                        // Continue without backup
                        backupResource = null;
                    }
                }

                // Load the old keystore with its correct provider
                KeyStore oldKs = createKeyStore(effectiveType, getKeyStoreProviderForType(effectiveType));
                LOGGER.log(
                        Level.FINE,
                        "Created old keystore instance: type=" + oldKs.getType() + ", provider="
                                + oldKs.getProvider().getName());
                try (InputStream fis = getResource().in()) {
                    oldKs.load(fis, passwd);
                    LOGGER.log(Level.FINE, "Loaded old keystore, aliases count: " + oldKs.size());
                } catch (Exception e) {
                    LOGGER.log(
                            Level.SEVERE,
                            "Failed to load old keystore: " + e.getClass().getName() + ": " + e.getMessage());
                    throw e;
                }
                // Create new keystore with the desired type
                String provider = getKeyStoreProviderForType(keystoreType);
                ks = createKeyStore(keystoreType, provider);
                ks.load(null, passwd);

                // Copy keys directly from old to new keystore
                // The copyKeyEntries method will normalize SecretKeys to SecretKeySpec when targeting JCEKS
                copyKeyEntries(oldKs, ks, passwd);

                // Ensure initial keys are present
                ensureInitialKeys();

                // Save the new keystore to the correct filename for the new type
                Resource newResource = securityManager.security().get(getDefaultFileName());
                try {
                    try (OutputStream fos = newResource.out()) {
                        ks.store(fos, passwd);
                    }
                    LOGGER.log(Level.FINE, "Wrote new keystore: " + newResource.name());
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Failed to write new keystore, attempting rollback: " + e.getMessage(), e);

                    // Rollback: restore from backup if available
                    if (backupResource != null && backupResource.getType() != Type.UNDEFINED) {
                        try {
                            java.nio.file.Files.copy(
                                    backupResource.file().toPath(),
                                    oldResource.file().toPath(),
                                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                            LOGGER.log(Level.FINE, "Rollback successful: restored from backup");
                        } catch (Exception rollbackEx) {
                            LOGGER.log(Level.SEVERE, "Rollback failed: " + rollbackEx.getMessage(), rollbackEx);
                        }
                    }
                    throw new IOException("Keystore migration failed", e);
                }

                // Update the cached resource to point to the new file
                keyStoreResource = newResource;

                // Delete the old keystore file now that migration succeeded
                // (backup is preserved for rollback)
                if (!oldResource.path().equals(newResource.path())) {
                    try {
                        oldResource.delete();
                        LOGGER.log(Level.INFO, "Deleted old keystore: " + oldResource.name());
                    } catch (Exception delEx) {
                        LOGGER.log(Level.WARNING,
                                "Could not delete old keystore " + oldResource.name()
                                        + " after migration (non-fatal): " + delEx.getMessage());
                    }
                }

                LOGGER.log(Level.INFO, "Keystore migration completed: " + effectiveType + " -> " + keystoreType);
            } else {
                // Type matches, load existing keystore
                String provider = getKeyStoreProviderForType(effectiveType);
                ks = createKeyStore(effectiveType, provider);
                try (InputStream fis = getResource().in()) {
                    ks.load(fis, passwd);
                }
            }
        } catch (Exception ex) {
            if (ex instanceof IOException exception) // avoid useless wrapping
            throw exception;
            throw new IOException(ex);
        } finally {
            securityManager.disposePassword(passwd);
        }
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#isKeystorePassword(java.lang.String)
     */
    @Override
    public boolean isKeyStorePassword(char[] password) throws IOException {
        if (password == null) return false;
        assertActivatedKeyStore();

        KeyStore testStore = null;
        try {
            String keystoreType = this.cachedKeyStoreType;
            String effectiveType = inferTypeFromPathOrDefault(getResource().path(), keystoreType);
            String provider = getKeyStoreProviderForType(effectiveType);

            testStore = createKeyStore(effectiveType, provider);
        } catch (KeyStoreException | NoSuchProviderException e1) {
            // should not happen, see assertActivatedKeyStore
            throw new RuntimeException(e1);
        }
        try (InputStream fis = getResource().in()) {
            testStore.load(fis, password);
        } catch (IOException e2) {
            // indicates invalid password
            return false;
        } catch (Exception e) {
            // should not happen, see assertActivatedKeyStore
            throw new RuntimeException(e);
        }
        return true;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#setSecretKey(java.lang.String, java.lang.String)
     */
    @Override
    public void setSecretKey(String alias, char[] key) throws IOException {
        assertActivatedKeyStore();
        SecretKey mySecretKey = deriveAesKey(toBytes(key));
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(mySecretKey);
        char[] passwd = securityManager.getMasterPassword();
        try {
            ks.setEntry(alias, skEntry, new KeyStore.PasswordProtection(passwd.clone()));
        } catch (KeyStoreException e) {
            throw new IOException(e);
        } finally {
            securityManager.disposePassword(passwd);
        }
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#setUserGroupKey(java.lang.String, java.lang.String)
     */
    @Override
    public void setUserGroupKey(String serviceName, char[] password) throws IOException {
        String alias = aliasForGroupService(serviceName);
        setSecretKey(alias, password);
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#removeKey(java.lang.String)
     */
    @Override
    public void removeKey(String alias) throws IOException {
        assertActivatedKeyStore();
        try {
            ks.deleteEntry(alias);
        } catch (KeyStoreException e) {
            throw new IOException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#storeKeyStore()
     */
    @Override
    public synchronized void storeKeyStore() throws IOException {
        // store away the keystore
        assertActivatedKeyStore();
        try (OutputStream fos = getResource().out()) {

            char[] passwd = securityManager.getMasterPassword();
            try {
                ks.store(fos, passwd);
            } catch (Exception e) {
                throw new IOException(e);
            } finally {
                securityManager.disposePassword(passwd);
            }
        }
    }

    /**
     * Derives a 32-byte AES {@link SecretKey} from raw key material using SHA-256.
     *
     * @throws IllegalStateException if SHA-256 is not available (required by the JVM specification)
     */
    private static SecretKey deriveAesKey(byte[] rawKeyBytes) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = digest.digest(rawKeyBytes);
            return new SecretKeySpec(keyBytes, DEFAULT_SECRET_KEY_ALGORITHM);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "SHA-256 is required for key derivation but is not available in this JVM", e);
        }
    }

    /** Creates initial key entries auto generated keys {@link #CONFIGPASSWORDKEY} */
    protected void addInitialKeys() throws IOException {
        // TODO:scramble
        RandomPasswordProvider randPasswdProvider = getSecurityManager().getRandomPassworddProvider();

        char[] configKey = randPasswdProvider.getRandomPasswordWithDefaultLength();
        SecretKey mySecretKey = deriveAesKey(toBytes(configKey));
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(mySecretKey);
        char[] passwd = securityManager.getMasterPassword();
        try {
            ks.setEntry(CONFIGPASSWORDKEY, skEntry, new KeyStore.PasswordProtection(passwd.clone()));
        } catch (KeyStoreException e) {
            throw new IOException(e);
        } finally {
            securityManager.disposePassword(passwd);
        }
    }

    /** Ensures initial keys are present, adding them if missing */
    protected void ensureInitialKeys() throws IOException {
        try {
            if (!ks.containsAlias(CONFIGPASSWORDKEY)) {
                addInitialKeys();
                storeKeyStore();
            }
        } catch (KeyStoreException | IOException e) {
            // Log the root cause but never delete an existing keystore — that would destroy
            // all stored secrets (user-group keys, config password key, etc.).
            // If this is a keystore type mismatch after a FIPS mode change, the caller should
            // use the explicit migrateKeyStore() path instead.
            LOGGER.log(
                    Level.SEVERE,
                    "Failed to verify/add initial keys in keystore. "
                            + "The keystore will NOT be deleted to avoid data loss. "
                            + "If FIPS mode was recently changed, a keystore migration may be required. "
                            + "Error: " + e.getMessage(),
                    e);
            throw new IOException(
                    "Keystore initialization failed — existing keystore preserved to avoid data loss", e);
        }
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#prepareForMasterPasswordChange(java.lang.String, java.lang.String)
     */
    @Override
    public void prepareForMasterPasswordChange(char[] oldPassword, char[] newPassword) throws IOException {

        Resource dir = getResource().parent();
        Resource newKSFile = dir.get(getPreparedFileName());
        if (newKSFile.getType() != Type.UNDEFINED) {
            newKSFile.delete();
        }

        try {
            Resource currentResource = getResource();
            String currentType = inferTypeFromPathOrDefault(currentResource.path(), this.cachedKeyStoreType);
            String currentProvider = getKeyStoreProviderForType(currentType);
            String targetType = this.cachedKeyStoreType;
            String targetProvider = getKeyStoreProviderForType(targetType);

            KeyStore oldKS = createKeyStore(currentType, currentProvider);
            KeyStore newKS = createKeyStore(targetType, targetProvider);

            try (InputStream fin = getResource().in()) {
                oldKS.load(fin, oldPassword);
            }

            newKS.load(null, newPassword);
            KeyStore.PasswordProtection protectionparam = new KeyStore.PasswordProtection(newPassword);

            Enumeration<String> enumeration = oldKS.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                Key key = oldKS.getKey(alias, oldPassword);
                KeyStore.Entry entry = null;
                if (key instanceof SecretKey secretKey) {
                    // Normalize SecretKeys for BCFKS: non-FIPS algorithms are rejected
                    if (BCFKS_KEYSTORE_TYPE.equals(targetType) && !isFipsApprovedAlgorithm(secretKey.getAlgorithm())) {
                        secretKey = deriveAesKey(secretKey.getEncoded());
                    }
                    entry = new KeyStore.SecretKeyEntry(secretKey);
                }
                if (key instanceof PrivateKey privateKey)
                    entry = new KeyStore.PrivateKeyEntry(privateKey, oldKS.getCertificateChain(alias));
                if (key instanceof PublicKey) entry = new KeyStore.TrustedCertificateEntry(oldKS.getCertificate(alias));
                if (entry == null)
                    LOGGER.warning("Unknown key in store, alias: "
                            + alias
                            + " class: "
                            + key.getClass().getName());
                else newKS.setEntry(alias, entry, protectionparam);
            }

            try (OutputStream fos = newKSFile.out()) {
                newKS.store(fos, newPassword);
            }

        } catch (Exception ex) {
            throw new IOException(ex);
        }
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#abortMasterPasswordChange()
     */
    @Override
    public void abortMasterPasswordChange() {}

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#commitMasterPasswordChange()
     */
    @Override
    public void commitMasterPasswordChange() throws IOException {
        Resource priorKSResource = getResource();
        Resource dir = priorKSResource.parent();
        Resource newKSFile = dir.get(getPreparedFileName());
        Resource targetKSFile = dir.get(getDefaultFileName());

        if (newKSFile.getType() == Type.UNDEFINED) {
            return; // nothing to do
        }

        if (priorKSResource.getType() == Type.UNDEFINED) {
            return; // not initialized
        }

        // Try to open with new password

        char[] passwd = securityManager.getMasterPassword();
        try {
            try (InputStream fin = newKSFile.in()) {
                String keystoreType = inferTypeFromPathOrDefault(newKSFile.path(), this.cachedKeyStoreType);
                String provider = getKeyStoreProviderForType(keystoreType);

                KeyStore newKS = createKeyStore(keystoreType, provider);

                newKS.load(fin, passwd);

                // to be sure, decrypt all keys
                Enumeration<String> enumeration = newKS.aliases();
                while (enumeration.hasMoreElements()) {
                    newKS.getKey(enumeration.nextElement(), passwd);
                }
            }

            if (priorKSResource.delete() == false) {
                LOGGER.severe("cannot delete " + priorKSResource.path());
                return;
            }

            if (targetKSFile.getType() != Type.UNDEFINED && !targetKSFile.path().equals(priorKSResource.path())) {
                if (targetKSFile.delete() == false) {
                    LOGGER.severe("cannot delete existing target " + targetKSFile.path());
                    return;
                }
            }

            if (newKSFile.renameTo(targetKSFile) == false) {
                String msg = "cannot rename " + newKSFile.path();
                msg += "to " + targetKSFile.path();
                msg += "Try to rename manually and restart";
                LOGGER.severe(msg);
                return;
            }
            this.keyStoreResource = targetKSFile;
            reloadKeyStore();
            LOGGER.info("Successfully changed master password");
        } catch (IOException e) {
            String msg = "Error creating new keystore: " + newKSFile.path();
            LOGGER.log(Level.WARNING, msg, e);
            throw e;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        } finally {
            securityManager.disposePassword(passwd);
        }
    }
}
