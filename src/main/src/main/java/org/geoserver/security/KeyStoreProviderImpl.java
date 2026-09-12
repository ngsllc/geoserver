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
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.geoserver.platform.resource.Resource;
import org.geoserver.platform.resource.Resource.Type;
import org.geoserver.platform.security.KeyStoreFormat;
import org.geoserver.platform.security.SecurityDefaults;
import org.geoserver.security.password.RandomPasswordProvider;
import org.geotools.util.logging.Logging;
import org.springframework.beans.factory.BeanNameAware;

/**
 * Class for GeoServer specific key management
 *
 * <p><strong>requires a master password</strong> form {@link MasterPasswordProvider}
 *
 * <p>The type of the keystore is JCEKS and can be used/modified with java tools like "keytool" from the command line. *
 *
 * @author christian
 */
public class KeyStoreProviderImpl implements BeanNameAware, KeyStoreProvider {

    public static final String DEFAULT_BEAN_NAME = "DefaultKeyStoreProvider";
    /** File name of a JCEKS keystore, the type GeoServer uses unless a deployment overrides it. */
    public static final String DEFAULT_FILE_NAME = "geoserver.jceks";

    /** File name the master password change writes, see {@link #prepareForMasterPasswordChange}. */
    public static final String PREPARED_FILE_NAME = DEFAULT_FILE_NAME + ".new";

    public static final String CONFIGPASSWORDKEY = "config:password:key";
    public static final String URLPARAMKEY = "url:param:key";
    public static final String USERGROUP_PREFIX = "ug:";
    public static final String USERGROUP_POSTFIX = ":key";

    protected static Logger LOGGER = Logging.getLogger("org.geoserver.security");
    protected String name;
    protected Resource keyStoreResource;
    protected KeyStore ks;

    /** Type used unless a deployment overrides it through {@link SecurityDefaults}. */
    public static final String KEYSTORETYPE = "JCEKS";

    /**
     * Keys are stored under this label. The entries hold random passwords of any length, not cipher keys, and BCFKS
     * would reject a length that does not fit the label: {@code AES} only accepts 16, 24 or 32 bytes. This label
     * accepts any length in both JCEKS and BCFKS. The label is never read back, only the bytes.
     */
    static final String KEY_ALGORITHM = "HmacSHA256";

    /**
     * Keys made from the stored secrets, see {@link KeyStoreProvider#getDerivedKey}. Cleared whenever the keystore
     * contents change, so an entry can never outlive the secret it was made from. Changing the master password is not
     * such a change: it locks the entries again, but the secrets stay the same.
     */
    private final Map<String, SecretKey> derivedKeys = new ConcurrentHashMap<>();

    GeoServerSecurityManager securityManager;

    static {
        // the keystore type can be one only the deployment's crypto provider implements, so it has
        // to be registered before the type is asked for. A servlet deployment gets there through
        // GeoserverInitStartupListener, but nothing else does.
        CryptoProviders.getProvider();
    }

    /** Not cached: a deployment may install the override after this provider is constructed. */
    static String keyStoreType() {
        return SecurityDefaults.get(SecurityDefaults.Setting.KEYSTORE_TYPE, KEYSTORETYPE);
    }

    /** Keystore file name, named after the type so a reader can tell the format from the file. */
    static String fileName() {
        return KeyStoreFormat.fileName(keyStoreType());
    }

    private static String preparedFileName() {
        return fileName() + ".new";
    }

    public KeyStoreProviderImpl() {}

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
        String fileName = fileName();
        // the name follows the configured type, which a deployment can override after this bean is built
        if (keyStoreResource == null || !fileName.equals(keyStoreResource.name())) {
            keyStoreResource = securityManager.security().get(fileName);
        }
        return keyStoreResource;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#reloadKeyStore()
     */
    @Override
    public void reloadKeyStore() throws IOException {
        derivedKeys.clear();
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
     * Opens or creates a {@link KeyStore} using the file named by {@link #fileName()}.
     *
     * <p>A keystore of another format left in place, by an installation that was configured for that format, has its
     * keys moved into a new keystore of the configured type, see {@link #migrate}. Throws an exception for an invalid
     * master key, or for a file named for the configured type that holds another format.
     */
    protected void assertActivatedKeyStore() throws IOException {
        if (ks != null) return;

        assertKeyStoreFormat();
        char[] passwd = securityManager.getMasterPassword();
        try {
            ks = KeyStore.getInstance(keyStoreType());
            if (getResource().getType() == Type.UNDEFINED) {
                ExistingKeyStore other = findKeyStoreOfAnotherFormat();
                if (other != null) {
                    migrate(other, passwd);
                } else { // create an empty one
                    ks.load(null, passwd);
                    addInitialKeys();
                    try (OutputStream fos = getResource().out()) {
                        ks.store(fos, passwd);
                    }
                }
            } else {
                try (InputStream fis = getResource().in()) {
                    ks.load(fis, passwd);
                }
            }
        } catch (Exception ex) {
            ks = null;
            if (ex instanceof IOException exception) // avoid useless wrapping
            throw exception;
            throw new IOException(ex);
        } finally {
            securityManager.disposePassword(passwd);
        }
    }

    /**
     * Refuses to open a keystore whose file is named for the configured type but holds another format.
     *
     * <p>Do not skip this check: without it the file fails to load with a message that says nothing about why, and an
     * administrator who deletes it to get past that loses the keys every stored password was encrypted with.
     */
    private void assertKeyStoreFormat() throws IOException {
        String type = keyStoreType();
        KeyStoreFormat found = KeyStoreFormat.detect(getResource());
        if (found != null && !found.name().equalsIgnoreCase(type)) {
            throw new IOException("Key store " + getResource().path() + " is a " + found + " file, but this "
                    + "installation is configured for " + type + ". Convert the file, or configure that type.");
        }
    }

    /** A keystore file of another format, found where the configured one should be. */
    private record ExistingKeyStore(Resource file, KeyStoreFormat format) {}

    /**
     * The keystore an installation configured for another format left behind, or null on a fresh data directory.
     * Finding one means keys, not a fresh install: GeoServer must never create an empty keystore next to it, or every
     * password encrypted with the old keys silently stops decrypting.
     */
    private ExistingKeyStore findKeyStoreOfAnotherFormat() throws IOException {
        for (KeyStoreFormat format : KeyStoreFormat.values()) {
            if (format.name().equalsIgnoreCase(keyStoreType())) {
                continue;
            }
            Resource other = securityManager.security().get(KeyStoreFormat.fileName(format.name()));
            if (other.getType() == Type.UNDEFINED) {
                continue;
            }
            KeyStoreFormat content = KeyStoreFormat.detect(other);
            if (content != null && content != format) {
                // the name and the first bytes disagree: say so, rather than fail to read it and leave the
                // administrator guessing which of the two is right
                throw new IOException("Key store " + other.path() + " is named for " + format + " but holds a "
                        + content + " file. Rename it to " + KeyStoreFormat.fileName(content.name())
                        + ", or convert it.");
            }
            return new ExistingKeyStore(other, format);
        }
        return null;
    }

    /**
     * Moves the keys of a keystore of another format into a new, empty keystore of the configured type, then writes it
     * and keeps the old file next to it with {@code .backup} appended. This is how a data directory written by a
     * regular GeoServer, with a JCEKS keystore, starts under FIPS with a BCFKS one and the same keys.
     *
     * <p>The old format has to be readable here: a provider has to offer it, and the master password has to open it.
     * JCEKS is one a FIPS operating system removes from Java, so such a directory is moved on a machine not yet in FIPS
     * mode, and the message says so.
     */
    private void migrate(ExistingKeyStore other, char[] passwd) throws IOException, GeneralSecurityException {
        String type = keyStoreType();
        Resource file = other.file();
        KeyStore source;
        try {
            source = KeyStore.getInstance(other.format().name());
        } catch (KeyStoreException e) {
            throw new IOException(
                    "Key store " + file.path() + " holds the keys of this installation, but it is a "
                            + other.format()
                            + " file and no crypto provider here offers that format, so its keys cannot be "
                            + "moved to " + type
                            + ". Start GeoServer once, with the same configuration, on a Java runtime that "
                            + "still offers " + other.format()
                            + ", such as one whose operating system is not in FIPS mode: "
                            + "the keys are moved there, and the data directory can then be used here. Or delete the file to "
                            + "start with new keys, after which every stored password has to be entered again.",
                    e);
        }
        try (InputStream in = file.in()) {
            source.load(in, passwd);
        } catch (IOException e) {
            throw new IOException("Could not read key store " + file.path() + " with the master password", e);
        }

        ks.load(null, passwd);
        KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(passwd);
        int moved = 0;
        Enumeration<String> aliases = source.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            KeyStore.Entry entry;
            if (source.isCertificateEntry(alias)) {
                ks.setEntry(alias, new KeyStore.TrustedCertificateEntry(source.getCertificate(alias)), null);
                moved++;
                continue;
            }
            Key key = source.getKey(alias, passwd);
            if (key instanceof SecretKey secretKey) {
                // the label is never read back, and the target format may refuse the one the old file used: keys
                // written by earlier versions carry "PBE", which BCFKS does not accept
                entry = new KeyStore.SecretKeyEntry(new SecretKeySpec(secretKey.getEncoded(), KEY_ALGORITHM));
            } else if (key instanceof PrivateKey privateKey) {
                entry = new KeyStore.PrivateKeyEntry(privateKey, source.getCertificateChain(alias));
            } else {
                LOGGER.warning("Key store " + file.path() + ": entry " + alias + " is of a kind that cannot be moved "
                        + (key == null ? "" : "(" + key.getClass().getName() + ")") + ", skipped");
                continue;
            }
            ks.setEntry(alias, entry, protection);
            moved++;
        }
        if (!ks.containsAlias(CONFIGPASSWORDKEY)) {
            addInitialKeys();
        }
        try (OutputStream out = getResource().out()) {
            ks.store(out, passwd);
        }

        Resource backup = file.parent().get(file.name() + ".backup");
        if (backup.getType() != Type.UNDEFINED) {
            backup.delete();
        }
        String kept = file.renameTo(backup) ? backup.path() : file.path() + " (could not be renamed)";
        LOGGER.warning("Key store " + file.path() + " moved from " + other.format() + " to " + type + " in "
                + getResource().path() + ": " + moved + " entries, the old file is kept as " + kept);
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
            testStore = KeyStore.getInstance(keyStoreType());
        } catch (KeyStoreException e1) {
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
    public SecretKey getDerivedKey(String alias, Function<char[], SecretKey> derivation) throws IOException {
        SecretKey cached = derivedKeys.get(alias);
        if (cached != null) {
            return cached;
        }
        SecretKey derived = KeyStoreProvider.super.getDerivedKey(alias, derivation);
        derivedKeys.put(alias, derived);
        return derived;
    }

    @Override
    public void setSecretKey(String alias, char[] key) throws IOException {
        derivedKeys.clear();
        assertActivatedKeyStore();
        SecretKey mySecretKey = new SecretKeySpec(toBytes(key), KEY_ALGORITHM);
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
        derivedKeys.clear();
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
        Resource newKSFile = dir.get(preparedFileName());
        if (newKSFile.getType() != Type.UNDEFINED) {
            newKSFile.delete();
        }

        try {
            KeyStore oldKS = KeyStore.getInstance(keyStoreType());
            try (InputStream fin = getResource().in()) {
                oldKS.load(fin, oldPassword);
            }

            KeyStore newKS = KeyStore.getInstance(keyStoreType());
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
        Resource dir = getResource().parent();
        Resource newKSFile = dir.get(preparedFileName());
        Resource oldKSFile = dir.get(fileName());

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
                KeyStore newKS = KeyStore.getInstance(keyStoreType());
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
