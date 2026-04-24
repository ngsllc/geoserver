/* (c) 2014 - 2016 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.web;

import java.security.GeneralSecurityException;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.servlet.http.HttpSession;
import org.apache.wicket.protocol.http.servlet.ServletWebRequest;
import org.apache.wicket.request.cycle.RequestCycle;
import org.apache.wicket.util.crypt.AbstractCrypt;
import org.apache.wicket.util.crypt.ICrypt;
import org.apache.wicket.util.crypt.ICryptFactory;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerSecurityManager;
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

    ICrypt NoCrypt = new ICrypt() {

        @Override
        public String decryptUrlSafe(String text) {
            return text;
        }

        @Override
        public String encryptUrlSafe(String plainText) {
            return plainText;
        }

        @Override
        @SuppressWarnings("removal")
        public void setKey(String key) {}
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

        StandardPBEByteEncryptor enc = new StandardPBEByteEncryptor();
        enc.setPasswordCharArray(key);
        // Use FIPS-compatible generators instead of Jasypt's defaults which use SHA1PRNG
        enc.setSaltGenerator(new org.geoserver.security.password.FipsRandomSaltGenerator());
        enc.setIvGenerator(new org.geoserver.security.password.FipsRandomIvGenerator());

        // Use FIPS-compatible algorithm — PBEWithHmacSHA256AndAES_128 works in both
        // FIPS and non-FIPS modes. Fall back to weaker algorithm only if the strong one
        // is not available AND we are NOT on a FIPS host (MD5+DES are blocked in FIPS).
        try {
            enc.setAlgorithm("PBEWithHmacSHA256AndAES_128");
            // Force initialization to detect unavailable algorithm early
            enc.initialize();
        } catch (Exception e) {
            if (org.geoserver.security.KeyStoreProviderImpl.isFipsMode()) {
                // On a FIPS host the only safe option is NoCrypt — MD5/DES are blocked
                manager.disposePassword(key);
                LOGGER.severe(
                        "PBEWithHmacSHA256AndAES_128 not available and FIPS mode is active; "
                                + "URL parameter encryption disabled: " + e.getMessage());
                s.setAttribute(ICRYPT_ATTR_NAME, NoCrypt);
                return NoCrypt;
            }
            LOGGER.warning(
                    "PBEWithHmacSHA256AndAES_128 not available for URL parameter encryption, "
                            + "falling back to PBEWITHMD5ANDDES: " + e.getMessage());
            enc = new StandardPBEByteEncryptor();
            enc.setPasswordCharArray(key);
            enc.setSaltGenerator(new org.geoserver.security.password.FipsRandomSaltGenerator());
            enc.setIvGenerator(new org.geoserver.security.password.FipsRandomIvGenerator());
            enc.setAlgorithm("PBEWITHMD5ANDDES");
        }
        // Dispose key after both paths have copied it via setPasswordCharArray
        manager.disposePassword(key);

        result = new CryptImpl(enc);
        s.setAttribute(ICRYPT_ATTR_NAME, result);
        return result;
    }
}
