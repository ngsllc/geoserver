/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.geoserver.security.password.LegacyPasswordFixtures.CANNED_CRYPT1;
import static org.geoserver.security.password.LegacyPasswordFixtures.CANNED_CRYPT2;
import static org.geoserver.security.password.LegacyPasswordFixtures.CANNED_PLAINTEXT;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import org.geoserver.data.test.SystemTestData;
import org.geoserver.security.GeoServerSecurityTestSupport;
import org.geoserver.test.SystemTest;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Values a GeoServer 2.x wrote with the password based encoders have to read back the same after the {@code crypt2}
 * reader stopped going through the provider, see {@link Pkcs12Pbe}. This runs against the canned test keystore, which
 * is the key those values were written under.
 */
@Category(SystemTest.class)
public class LegacyPasswordEncoderCompatibilityTest extends GeoServerSecurityTestSupport {

    @Before
    public void cannedKeyStoreOnly() {
        assumeTrue(
                "the values were written under the canned keystore, which this crypto provider cannot read",
                SystemTestData.canReadCannedSecurityDirectory());
    }

    @Test
    public void testCrypt2ReadsWithoutTheProvider() {
        GeoServerPBEPasswordEncoder encoder =
                (GeoServerPBEPasswordEncoder) getSecurityManager().loadPasswordEncoder("strongPbePasswordEncoder");
        assertTrue(encoder.canDecode());

        assertEquals(CANNED_PLAINTEXT, encoder.decode(CANNED_CRYPT2));
        assertArrayEquals(CANNED_PLAINTEXT.toCharArray(), encoder.decodeToCharArray(CANNED_CRYPT2));
        assertTrue(encoder.isPasswordValid(CANNED_CRYPT2, CANNED_PLAINTEXT, null));
        assertTrue(encoder.isPasswordValid(CANNED_CRYPT2, CANNED_PLAINTEXT.toCharArray(), null));
        assertFalse(encoder.isPasswordValid(CANNED_CRYPT2, "upstream-store-secreT", null));
        assertFalse(
                "a damaged value is a wrong password, not an error", encoder.isPasswordValid("crypt2:AAAA", "x", null));
    }

    /** What the provider writes today the reader still has to read, or nothing written from now on could be. */
    @Test
    public void testCrypt2RoundTripsThroughTheReader() {
        JasyptDefaults.assumeStrongPbeUsable();
        GeoServerPBEPasswordEncoder encoder =
                (GeoServerPBEPasswordEncoder) getSecurityManager().loadPasswordEncoder("strongPbePasswordEncoder");
        assertTrue(encoder.isCipherAvailable());

        String encoded = encoder.encodePassword("fresh-secret", null);
        assertTrue(encoded.startsWith("crypt2:"));
        assertEquals("fresh-secret", encoder.decode(encoded));
        assertTrue(encoder.isPasswordValid(encoded, "fresh-secret", null));
    }

    @Test
    public void testCrypt1StillReads() {
        JasyptDefaults.assumePbeUsable();
        GeoServerPBEPasswordEncoder encoder =
                (GeoServerPBEPasswordEncoder) getSecurityManager().loadPasswordEncoder("pbePasswordEncoder");

        assertEquals(CANNED_PLAINTEXT, encoder.decode(CANNED_CRYPT1));
        assertTrue(encoder.isPasswordValid(CANNED_CRYPT1, CANNED_PLAINTEXT, null));
        assertFalse(encoder.isPasswordValid(CANNED_CRYPT1, "other", null));
    }

    /** The helper that reads store passwords dispatches by prefix, so both old forms have to reach the right reader. */
    @Test
    public void testConfigurationHelperReadsBothForms() {
        ConfigurationPasswordEncryptionHelper helper = getSecurityManager().getConfigPasswordEncryptionHelper();
        assertEquals(CANNED_PLAINTEXT, helper.decode(CANNED_CRYPT2));
        JasyptDefaults.assumePbeUsable();
        assertEquals(CANNED_PLAINTEXT, helper.decode(CANNED_CRYPT1));
    }
}
