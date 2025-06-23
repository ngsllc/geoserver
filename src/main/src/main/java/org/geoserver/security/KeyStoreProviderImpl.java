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
 * <p><strong>requires a master password</strong> form {@link MasterPasswordProviderImpl}
 *
 * <p>The type of the keystore can be configured via the GEOSERVER_KEYSTORE_TYPE environment variable. If not set,
 * defaults to JCEKS. Supported types include JCEKS, BCFKS, and others supported by the JVM. The keystore can be
 * used/modified with java tools like "keytool" from the command line.
 *
 * @author christian
 */
public class KeyStoreProviderImpl implements BeanNameAware, KeyStoreProvider {

    public static final String DEFAULT_BEAN_NAME = "DefaultKeyStoreProvider";
    public static final String KEYSTORE_TYPE_ENV_VAR = "GEOSERVER_KEYSTORE_TYPE";
    public static final String DEFAULT_KEYSTORE_TYPE = "JCEKS";
    public static final String BCFKS_KEYSTORE_TYPE = "BCFKS";
    public static final String BCFIPS_PROVIDER = "BCFIPS";

    // Dynamic file names based on keystore type
    private String defaultFileName;
    private String preparedFileName;

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
        initializeFileNames();
    }

    /** Gets the keystore type from environment variable or defaults to JCEKS */
    public static String getKeyStoreType() {
        String envType = System.getenv(KEYSTORE_TYPE_ENV_VAR);
        if (envType != null && !envType.trim().isEmpty()) {
            return envType.trim();
        }
        String propType = System.getProperty(KEYSTORE_TYPE_ENV_VAR);
        if (propType != null && !propType.trim().isEmpty()) {
            return propType.trim();
        }
        return DEFAULT_KEYSTORE_TYPE;
    }

    /** Gets the appropriate provider for the keystore type */
    public static String getKeyStoreProvider() {
        String keystoreType = getKeyStoreType();
        return getKeyStoreProviderForType(keystoreType);
    }

    /** Gets the appropriate provider for a specific keystore type */
    public static String getKeyStoreProviderForType(String keystoreType) {
        if (BCFKS_KEYSTORE_TYPE.equals(keystoreType)) {
            return BCFIPS_PROVIDER;
        }
        return null; // Use default provider for other types
    }

    /** Initialize file names based on the keystore type */
    private void initializeFileNames() {
        String keystoreType = getKeyStoreType();
        String extension = keystoreType.toLowerCase();
        this.defaultFileName = "geoserver." + extension;
        this.preparedFileName = "geoserver." + extension + ".new";
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
            keyStoreResource = securityManager.security().get(getDefaultFileName());
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
            String keystoreType = getKeyStoreType();
            String provider = getKeyStoreProvider();

            // Register BouncyCastle provider if needed
            if (BCFKS_KEYSTORE_TYPE.equals(keystoreType) && java.security.Security.getProvider("BC") == null) {
                try {
                    Class<?> providerClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                    java.security.Provider bcProvider = (java.security.Provider)
                            providerClass.getDeclaredConstructor().newInstance();
                    java.security.Security.addProvider(bcProvider);
                } catch (Exception e) {
                    throw new IOException(
                            "BouncyCastle provider not available. Please add BouncyCastle to the classpath.", e);
                }
            }

            // Create keystore instance
            if (provider != null) {
                ks = java.security.KeyStore.getInstance(keystoreType, provider);
            } else {
                ks = java.security.KeyStore.getInstance(keystoreType);
            }

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
            if (ex instanceof IOException) // avoid useless wrapping
            throw (IOException) ex;
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
            String keystoreType = getKeyStoreType();
            String provider = getKeyStoreProvider();

            if (provider != null) {
                testStore = KeyStore.getInstance(keystoreType, provider);
            } else {
                testStore = KeyStore.getInstance(keystoreType);
            }
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
        SecretKey mySecretKey = new SecretKeySpec(toBytes(key), "AES");
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
            String keystoreType = getKeyStoreType();
            String provider = getKeyStoreProvider();

            KeyStore oldKS;
            KeyStore newKS;

            if (provider != null) {
                oldKS = KeyStore.getInstance(keystoreType, provider);
                newKS = KeyStore.getInstance(keystoreType, provider);
            } else {
                oldKS = KeyStore.getInstance(keystoreType);
                newKS = KeyStore.getInstance(keystoreType);
            }

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
                if (key instanceof SecretKey) entry = new KeyStore.SecretKeyEntry((SecretKey) key);
                if (key instanceof PrivateKey)
                    entry = new KeyStore.PrivateKeyEntry((PrivateKey) key, oldKS.getCertificateChain(alias));
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
        Resource dir = getResource().parent();
        Resource newKSFile = dir.get(getPreparedFileName());
        Resource oldKSFile = dir.get(getDefaultFileName());

        if (newKSFile.getType() == Type.UNDEFINED) {
            return; // nothing to do
        }

        if (oldKSFile.getType() == Type.UNDEFINED) {
            return; // not initialized
        }

        // Try to open with new password

        char[] passwd = securityManager.getMasterPassword();
        try {
            try (InputStream fin = newKSFile.in()) {
                String keystoreType = getKeyStoreType();
                String provider = getKeyStoreProvider();

                KeyStore newKS;
                if (provider != null) {
                    newKS = KeyStore.getInstance(keystoreType, provider);
                } else {
                    newKS = KeyStore.getInstance(keystoreType);
                }

                newKS.load(fin, passwd);

                // to be sure, decrypt all keys
                Enumeration<String> enumeration = newKS.aliases();
                while (enumeration.hasMoreElements()) {
                    newKS.getKey(enumeration.nextElement(), passwd);
                }
            }

            if (oldKSFile.delete() == false) {
                LOGGER.severe("cannot delete " + oldKSFile.path());
                return;
            }

            if (newKSFile.renameTo(oldKSFile) == false) {
                String msg = "cannot rename " + newKSFile.path();
                msg += "to " + oldKSFile.path();
                msg += "Try to rename manually and restart";
                LOGGER.severe(msg);
                return;
            }
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
