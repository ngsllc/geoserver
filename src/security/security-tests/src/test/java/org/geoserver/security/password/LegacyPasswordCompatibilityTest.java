/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.geoserver.security.password.LegacyPasswordFixtures.CRYPT1;
import static org.geoserver.security.password.LegacyPasswordFixtures.CRYPT2;
import static org.geoserver.security.password.LegacyPasswordFixtures.PLAINTEXT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import javax.crypto.SecretKey;
import org.geoserver.security.GeoServerSecurityTestSupport;
import org.geoserver.security.KeyStoreProviderImpl;
import org.geoserver.test.SystemTest;
import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * A data directory created by an earlier GeoServer version keeps a JCEKS keystore whose keys are the raw bytes of a
 * random password. In non-FIPS mode nothing is migrated, and every password stored by that version must still decrypt.
 */
@Category(SystemTest.class)
public class LegacyPasswordCompatibilityTest extends GeoServerSecurityTestSupport {

    @Test
    public void testKeystoreKeyIsRecognizedAsLegacy() throws Exception {
        SecretKey key = getSecurityManager().getKeyStoreProvider().getSecretKey(KeyStoreProviderImpl.CONFIGPASSWORDKEY);
        assertEquals("PBE", key.getAlgorithm());
        assertEquals(40, key.getEncoded().length);
        assertTrue(GeoServerPBEPasswordEncoder.isLegacyKey(key));
    }

    @Test
    public void testUpstreamStrongPasswordDecodes() throws Exception {
        GeoServerPBEPasswordEncoder strong = pbeEncoder("strongPbePasswordEncoder");
        assertEquals(PLAINTEXT, strong.decode(CRYPT2));
        assertTrue(strong.isPasswordValid(CRYPT2, PLAINTEXT, null));
        // and the helper the catalog uses to read data store passwords
        assertEquals(
                PLAINTEXT,
                getSecurityManager().getConfigPasswordEncryptionHelper().decode(CRYPT2));
        // new values are written in the same, upstream compatible format
        String encoded = strong.encodePassword("new-secret", null);
        assertTrue(encoded.startsWith("crypt2:"));
        assertNotEquals(CRYPT2, encoded);
        assertEquals("new-secret", strong.decode(encoded));
    }

    @Test
    public void testUpstreamWeakPasswordDecodes() throws Exception {
        Assume.assumeTrue("legacy MD5/DES not available on this JVM", legacyAlgorithmAvailable());
        GeoServerPBEPasswordEncoder weak = pbeEncoder("pbePasswordEncoder");
        assertEquals(PLAINTEXT, weak.decode(CRYPT1));
        assertTrue(weak.isPasswordValid(CRYPT1, PLAINTEXT, null));
        assertEquals(
                PLAINTEXT,
                getSecurityManager().getConfigPasswordEncryptionHelper().decode(CRYPT1));
        String encoded = weak.encodePassword("new-secret", null);
        assertTrue(encoded.startsWith("crypt1:"));
        assertEquals("new-secret", weak.decode(encoded));
    }

    private GeoServerPBEPasswordEncoder pbeEncoder(String name) throws Exception {
        return (GeoServerPBEPasswordEncoder) getSecurityManager().loadPasswordEncoder(name);
    }

    private static boolean legacyAlgorithmAvailable() {
        try {
            javax.crypto.Cipher.getInstance(URLMasterPasswordProvider.LEGACY_PBE_ALGORITHM);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
