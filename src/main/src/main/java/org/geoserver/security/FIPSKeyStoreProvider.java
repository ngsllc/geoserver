/*
 * (c) 2024 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.geoserver.platform.resource.Resource;
import org.geotools.util.logging.Logging;

/**
 * FIPS-compatible keystore provider that can work in FIPS-enabled environments. This provider automatically detects
 * FIPS mode and uses appropriate keystore types.
 */
public class FIPSKeyStoreProvider extends KeyStoreProviderImpl {

    private static final Logger LOGGER = Logging.getLogger(FIPSKeyStoreProvider.class);

    private static final String FIPS_PROVIDER_CLASS = "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";
    private static final String STANDARD_PROVIDER_CLASS = "org.bouncycastle.jce.provider.BouncyCastleProvider";

    private boolean fipsMode = false;
    private Provider cryptoProvider;

    public FIPSKeyStoreProvider() {
        super();
        initializeFIPSProvider();
    }

    /** Initialize the appropriate crypto provider based on FIPS availability */
    private void initializeFIPSProvider() {
        // Check if we're in a FIPS environment
        String fipsMode = System.getProperty("com.redhat.fips");
        if (fipsMode != null && fipsMode.equals("true")) {
            this.fipsMode = true;
            LOGGER.info("FIPS mode detected, using FIPS-compliant crypto provider");
        }

        // Try to load FIPS provider first
        try {
            Class<?> fipsProviderClass = Class.forName(FIPS_PROVIDER_CLASS);
            cryptoProvider =
                    (Provider) fipsProviderClass.getDeclaredConstructor().newInstance();
            Security.addProvider(cryptoProvider);
            this.fipsMode = true;
            LOGGER.info("FIPS-compliant BouncyCastle provider loaded successfully");
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "FIPS provider not available, falling back to standard provider", e);

            // Fall back to standard provider
            try {
                Class<?> standardProviderClass = Class.forName(STANDARD_PROVIDER_CLASS);
                cryptoProvider = (Provider)
                        standardProviderClass.getDeclaredConstructor().newInstance();
                Security.addProvider(cryptoProvider);
                LOGGER.info("Standard BouncyCastle provider loaded successfully");
            } catch (Exception ex) {
                LOGGER.log(Level.WARNING, "No BouncyCastle provider available", ex);
            }
        }
    }

    /** Override the keystore type to use FIPS-compliant types when in FIPS mode */
    @Override
    public Resource getResource() {
        if (fipsMode) {
            // In FIPS mode, prefer PKCS12
            String keystoreType = System.getenv(KEYSTORE_TYPE_ENV_VAR);
            if (keystoreType == null || keystoreType.isEmpty()) {
                // Set PKCS12 as default for FIPS mode
                System.setProperty(KEYSTORE_TYPE_ENV_VAR, "PKCS12");
                LOGGER.info("Setting PKCS12 as default keystore type for FIPS mode");
            }
        }
        return super.getResource();
    }

    /** Override keystore creation to use FIPS provider when available */
    @Override
    protected void assertActivatedKeyStore() throws IOException {
        if (ks == null) {
            try {
                String keystoreType = getKeyStoreType();
                String provider = getKeyStoreProvider();

                if (fipsMode && cryptoProvider != null) {
                    // Use the FIPS provider for keystore creation
                    ks = KeyStore.getInstance(keystoreType, cryptoProvider.getName());
                    LOGGER.info("Created keystore with FIPS provider: " + cryptoProvider.getName());
                } else if (provider != null) {
                    // Use the specified provider
                    ks = KeyStore.getInstance(keystoreType, provider);
                    LOGGER.info("Created keystore with provider: " + provider);
                } else {
                    // Use default provider
                    ks = KeyStore.getInstance(keystoreType);
                    LOGGER.info("Created keystore with default provider");
                }

                // Load the keystore
                char[] passwd = securityManager.getMasterPassword();
                try {
                    if (getResource().getType() == Resource.Type.RESOURCE) {
                        ks.load(getResource().in(), passwd);
                    } else {
                        ks.load(null, passwd);
                    }
                } finally {
                    securityManager.disposePassword(passwd);
                }

                LOGGER.info("Keystore loaded successfully with type: " + keystoreType);

            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Failed to create keystore with current provider, trying default", e);
                // Fall back to parent implementation
                super.assertActivatedKeyStore();
            }
        }
    }

    /** Check if running in FIPS mode */
    public boolean isFIPSMode() {
        return fipsMode;
    }

    /** Get the current crypto provider */
    public Provider getCryptoProvider() {
        return cryptoProvider;
    }

    /** Get the default keystore type for FIPS mode */
    public String getDefaultKeyStoreType() {
        if (fipsMode) {
            String keystoreType = System.getenv(KEYSTORE_TYPE_ENV_VAR);
            if (keystoreType != null && !keystoreType.isEmpty()) {
                return keystoreType;
            }
            return "PKCS12"; // FIPS-compliant default
        }
        return getKeyStoreType();
    }
}
