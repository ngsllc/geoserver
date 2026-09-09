/* (c) 2014 - 2016 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.web;

import jakarta.servlet.http.HttpSession;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import org.apache.wicket.protocol.http.servlet.ServletWebRequest;
import org.apache.wicket.request.cycle.RequestCycle;
import org.apache.wicket.util.crypt.AbstractCrypt;
import org.apache.wicket.util.crypt.ICrypt;
import org.apache.wicket.util.crypt.ICryptFactory;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.KeyStoreProviderImpl;
import org.geoserver.security.password.FipsRandomIvGenerator;
import org.geoserver.security.password.FipsRandomSaltGenerator;
import org.geotools.util.logging.Logging;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;

/**
 * Encryptor factory for apache wicket
 *
 * @author christian
 */
public class GeoserverWicketEncrypterFactory implements ICryptFactory {

    static ICryptFactory Factory;
    protected static Logger LOGGER = Logging.getLogger("org.geoserver.security");
    static final String ICRYPT_ATTR_NAME = "__ICRYPT";

    /** Strong algorithm used for URL parameter encryption, provided by BCFIPS */
    static final String FIPS_PBE_ALGORITHM = KeyStoreProviderImpl.FIPS_PBE_ALGORITHM;

    /** Jasypt default, only used in non-FIPS mode when BCFIPS is not available */
    static final String FALLBACK_ALGORITHM = "PBEWITHMD5ANDDES";

    /**
     * Builds an encryptor for the given key and algorithm. Uses FIPS-compatible salt and IV generators instead of
     * Jasypt's defaults which use SHA1PRNG. The BCFIPS provider is pinned when it is available so that the lookup does
     * not depend on provider ordering.
     */
    static StandardPBEByteEncryptor newEncryptor(char[] key, String algorithm, boolean useBcFips) {
        StandardPBEByteEncryptor enc = new StandardPBEByteEncryptor();
        enc.setPasswordCharArray(key);
        enc.setSaltGenerator(new FipsRandomSaltGenerator());
        enc.setIvGenerator(new FipsRandomIvGenerator());
        enc.setAlgorithm(algorithm);
        if (useBcFips) {
            enc.setProviderName(KeyStoreProviderImpl.BCFIPS_PROVIDER);
        }
        return enc;
    }

    ICrypt NoCrypt = new ICrypt() {

        @Override
        public String decryptUrlSafe(String text) {
            return text;
        }

        @Override
        public String encryptUrlSafe(String plainText) {
            return plainText;
        }
    };

    static class CryptImpl extends AbstractCrypt {
        protected StandardPBEByteEncryptor enc;

        CryptImpl(StandardPBEByteEncryptor enc) {
            this.enc = enc;
        }

        @Override
        protected byte[] crypt(byte[] input, int mode) throws GeneralSecurityException {
            if (mode == Cipher.ENCRYPT_MODE) {
                return enc.encrypt(input);
            } else {
                return enc.decrypt(input);
            }
        }
    }

    /**
     * Look up in the Spring Context for an implementation of {@link ICryptFactory} if nothing found use this default.
     */
    public static ICryptFactory get() {
        if (Factory != null) return Factory;
        Factory = GeoServerExtensions.bean(ICryptFactory.class);
        if (Factory == null) Factory = new GeoserverWicketEncrypterFactory();
        return Factory;
    }

    protected GeoserverWicketEncrypterFactory() {}

    @Override
    public ICrypt newCrypt() {
        RequestCycle cycle = RequestCycle.get();
        ServletWebRequest req = (ServletWebRequest) cycle.getRequest();
        HttpSession s = req.getContainerRequest().getSession(false);
        if (s != null) {
            return getEncrypterFromSession(s);
        } else {
            LOGGER.warning("No session available to get url parameter encrypter");
            return NoCrypt;
        }
    }

    protected ICrypt getEncrypterFromSession(HttpSession s) {
        ICrypt result = (ICrypt) s.getAttribute(ICRYPT_ATTR_NAME);
        if (result != null) return result;

        GeoServerSecurityManager manager = GeoServerApplication.get().getSecurityManager();
        char[] key = manager.getRandomPassworddProvider().getRandomPasswordWithDefaultLength();

        // The strong algorithm is provided by BCFIPS only, so register the provider first. This works in both
        // FIPS and non-FIPS mode as long as bc-fips is on the classpath. Fall back to the weaker Jasypt default
        // only if the strong one is not available AND we are NOT on a FIPS host (MD5+DES are blocked in FIPS).
        StandardPBEByteEncryptor enc;
        try {
            enc = newEncryptor(key, FIPS_PBE_ALGORITHM, KeyStoreProviderImpl.ensureBcFipsProviderRegistered());
            // Force initialization to detect unavailable algorithm early
            enc.initialize();
        } catch (Exception e) {
            if (KeyStoreProviderImpl.isFipsMode()) {
                // On a FIPS host the only safe option is NoCrypt — MD5/DES are blocked
                manager.disposePassword(key);
                LOGGER.severe(FIPS_PBE_ALGORITHM + " not available and FIPS mode is active; "
                        + "URL parameter encryption disabled: " + e.getMessage());
                s.setAttribute(ICRYPT_ATTR_NAME, NoCrypt);
                return NoCrypt;
            }
            LOGGER.warning(FIPS_PBE_ALGORITHM + " not available for URL parameter encryption, falling back to "
                    + FALLBACK_ALGORITHM + ": " + e.getMessage());
            enc = newEncryptor(key, FALLBACK_ALGORITHM, false);
        }
        // Dispose key after both paths have copied it via setPasswordCharArray
        manager.disposePassword(key);

        result = new CryptImpl(enc);
        s.setAttribute(ICRYPT_ATTR_NAME, result);
        return result;
    }
}
