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
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
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
 * Class for Geoserver specific key management
 *
 * <p><strong>requires a master password</strong> form {@link MasterPasswordProvider}
 *
 * <p>The type of the keystore can be configured via the GEOSERVER_KEYSTORE_TYPE environment variable. If not set,
 * defaults to JCEKS in non-FIPS mode and PKCS12 in FIPS mode. Supported types include JCEKS, BCFKS, and others supported by the JVM. The keystore can be
 * used/modified with java tools like "keytool" from the command line.
 *
 * @author christian
 */
public class KeyStoreProviderImpl implements BeanNameAware, KeyStoreProvider {

    public static final String DEFAULT_BEAN_NAME = "DefaultKeyStoreProvider";
    public static final String KEYSTORE_TYPE_ENV_VAR = "GEOSERVER_KEYSTORE_TYPE";
    public static final String KEYSTORE_PROVIDER_ENV_VAR = "GEOSERVER_KEYSTORE_PROVIDER";
    public static final String DEFAULT_KEYSTORE_TYPE = "JCEKS";
    public static final String BCFKS_KEYSTORE_TYPE = "BCFKS";
    public static final String PKCS12_KEYSTORE_TYPE = "PKCS12";
    public static final String BCFIPS_PROVIDER = "BCFIPS";
    public static final String BC_PROVIDER = "BC";
    public static final String DEFAULT_SECRET_KEY_ALGORITHM = "AES";
    public static final String FIPS_PROPERTY_NAME = "com.redhat.fips";

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
    protected Resource keyStoreResource;
    protected KeyStore ks;

    GeoServerSecurityManager securityManager;

    public KeyStoreProviderImpl() {
        this.cachedKeyStoreType = getKeyStoreType();
        initializeFileNames();
    }

    /** Gets the keystore type from configuration, defaulting based on environment (FIPS→PKCS12, else JCEKS) */
    public static String getKeyStoreType() {
        String envType = System.getenv(KEYSTORE_TYPE_ENV_VAR);
        if (envType != null && !envType.trim().isEmpty()) {
            return envType.trim();
        }
        String propType = System.getProperty(KEYSTORE_TYPE_ENV_VAR);
        if (propType != null && !propType.trim().isEmpty()) {
            return propType.trim();
        }
        // Default based on environment
        return isFipsEnvironment() ? PKCS12_KEYSTORE_TYPE : DEFAULT_KEYSTORE_TYPE;
    }

    /** Detects if the runtime indicates a FIPS-enabled environment */
    private static boolean isFipsEnvironment() {
        String fipsProperty = System.getProperty(FIPS_PROPERTY_NAME);
        return "true".equals(fipsProperty);
    }

    /** Gets the appropriate provider for the keystore type */
    public static String getKeyStoreProvider() {
        String keystoreType = getKeyStoreType();
        return getKeyStoreProviderForType(keystoreType);
    }

    /** Gets the appropriate provider for a specific keystore type */
    public static String getKeyStoreProviderForType(String keystoreType) {
        // Check environment variable first
        String envProvider = System.getenv(KEYSTORE_PROVIDER_ENV_VAR);
        if (envProvider != null && !envProvider.trim().isEmpty()) {
            return envProvider.trim();
        }

        if (BCFKS_KEYSTORE_TYPE.equals(keystoreType)) {
            // Try to find available BouncyCastle provider
            if (java.security.Security.getProvider(BCFIPS_PROVIDER) != null) {
                return BCFIPS_PROVIDER;
            } else if (java.security.Security.getProvider(BC_PROVIDER) != null) {
                return BC_PROVIDER;
            } else {
                // Default to BC if no provider is found (will be registered later)
                return BC_PROVIDER;
            }
        }
        return null; // Use default provider for other types
    }

    /**
     * Infer keystore type from the file path extension, falling back to the provided default type. Recognized
     * extensions: .jceks, .jks, .bcfks, .pkcs12
     */
    private static final java.util.Map<String, String> EXTENSION_TO_TYPE_MAP = new java.util.HashMap<>();

    static {
        EXTENSION_TO_TYPE_MAP.put(".jceks", "JCEKS");
        EXTENSION_TO_TYPE_MAP.put(".jks", "JKS");
        EXTENSION_TO_TYPE_MAP.put(".bcfks", "BCFKS");
        EXTENSION_TO_TYPE_MAP.put(".pkcs12", PKCS12_KEYSTORE_TYPE);
        EXTENSION_TO_TYPE_MAP.put(".p12", PKCS12_KEYSTORE_TYPE);
        EXTENSION_TO_TYPE_MAP.put(".pfx", PKCS12_KEYSTORE_TYPE);
    }

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

    private void ensureProviderAvailable(String keystoreType, String provider) {
        if (!BCFKS_KEYSTORE_TYPE.equals(keystoreType)) {
            return;
        }
        if (provider != null && java.security.Security.getProvider(provider) == null) {
            try {
                if (BCFIPS_PROVIDER.equals(provider)) {
                    // Try to load BouncyCastle FIPS provider
                    // Note: This may fail if FIPS libraries are not in classpath or if regular BC provider is already loaded.
                    try {
                        Class<?> providerClass =
                                Class.forName("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider");
                        java.security.Provider bcProvider = (java.security.Provider)
                                providerClass.getDeclaredConstructor().newInstance();
                        java.security.Security.addProvider(bcProvider);
                        LOGGER.info("Successfully registered BouncyCastle FIPS provider");
                    } catch (ClassNotFoundException e) {
                        LOGGER.log(
                                Level.WARNING,
                                "BouncyCastle FIPS provider not available in classpath. "
                                        + "Ensure bc-fips dependency is included for FIPS mode.");
                        // Fallback to regular BC provider
                        fallbackToRegularBCProvider();
                    } catch (Exception e) {
                        if (e.getCause() instanceof SecurityException
                                && e.getCause().getMessage().contains("sealing violation")) {
                            LOGGER.log(
                                    Level.WARNING,
                                    "BouncyCastle FIPS provider cannot be loaded due to package sealing conflict. "
                                            + "This typically occurs when both regular and FIPS BouncyCastle providers are in classpath. "
                                            + "For FIPS mode, ensure only FIPS providers are used.");
                            // Fallback to regular BC provider
                            fallbackToRegularBCProvider();
                        } else {
                            LOGGER.log(
                                    Level.WARNING,
                                    "Failed to register BouncyCastle FIPS provider: " + e.getMessage(),
                                    e);
                            fallbackToRegularBCProvider();
                        }
                    }
                } else if (BC_PROVIDER.equals(provider)) {
                    fallbackToRegularBCProvider();
                }
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Failed to register BouncyCastle provider: " + e.getMessage(), e);
            }
        }
    }

    private void fallbackToRegularBCProvider() {
        try {
            // Check if regular BC provider is already available
            if (java.security.Security.getProvider(BC_PROVIDER) != null) {
                return;
            }

            Class<?> providerClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            java.security.Provider bcProvider = (java.security.Provider)
                    providerClass.getDeclaredConstructor().newInstance();
            java.security.Security.addProvider(bcProvider);
            LOGGER.info("Successfully registered standard BouncyCastle provider as fallback");
        } catch (Exception e) {
            LOGGER.log(
                    Level.WARNING,
                    "Failed to register standard BouncyCastle provider as fallback: " + e.getMessage(),
                    e);
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
        if (keyStoreResource == null) {
            // Prefer the configured default file name
            Resource baseDir = securityManager.security();
            Resource candidate = baseDir.get(getDefaultFileName());
            if (candidate.getType() == Type.UNDEFINED) {
                // Backward-compatibility: if default not found, try legacy/common filenames
                Resource legacyJceks = baseDir.get("geoserver.jceks");
                Resource legacyJks = baseDir.get("geoserver.jks");
                Resource legacyBcfks = baseDir.get("geoserver.bcfks");

                if (legacyJceks.getType() != Type.UNDEFINED) {
                    candidate = legacyJceks;
                } else if (legacyJks.getType() != Type.UNDEFINED) {
                    candidate = legacyJks;
                } else if (legacyBcfks.getType() != Type.UNDEFINED) {
                    candidate = legacyBcfks;
                }
            }
            keyStoreResource = candidate;
        }
        return keyStoreResource;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#reloadKeyStore()
     */
    @Override
    public void reloadKeyStore() throws IOException {
        ks = null;
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
    protected void assertActivatedKeyStore() throws IOException {
        if (ks != null) return;

        char[] passwd = securityManager.getMasterPassword();
        try {
            String keystoreType = this.cachedKeyStoreType;
            String effectiveType = inferTypeFromPathOrDefault(getResource().path(), keystoreType);
            String provider = getKeyStoreProviderForType(effectiveType);

            ks = createKeyStore(effectiveType, provider);

            if (getResource().getType() == Type.UNDEFINED) { // create an empty one
                ks.load(null, passwd);
                addInitialKeys();
                try (OutputStream fos = getResource().out()) {
                    ks.store(fos, passwd);
                }
            } else {
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
        // Use AES algorithm for compatibility with different keystore types
        SecretKey mySecretKey = new SecretKeySpec(toBytes(key), DEFAULT_SECRET_KEY_ALGORITHM);
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(mySecretKey);
        char[] passwd = securityManager.getMasterPassword();
        try {
            ks.setEntry(alias, skEntry, new KeyStore.PasswordProtection(passwd));
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
    public void storeKeyStore() throws IOException {
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

    /** Creates initial key entries auto generated keys {@link #CONFIGPASSWORDKEY} */
    protected void addInitialKeys() throws IOException {
        // TODO:scramble
        RandomPasswordProvider randPasswdProvider = getSecurityManager().getRandomPassworddProvider();

        char[] configKey = randPasswdProvider.getRandomPasswordWithDefaultLength();
        setSecretKey(CONFIGPASSWORDKEY, configKey);
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
                if (key instanceof SecretKey secretKey) entry = new KeyStore.SecretKeyEntry(secretKey);
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
