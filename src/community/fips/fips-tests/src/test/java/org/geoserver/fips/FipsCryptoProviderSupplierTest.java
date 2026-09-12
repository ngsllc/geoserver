/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.fips;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeTrue;

import java.security.SecureRandom;
import org.geoserver.security.CryptoProviders;
import org.junit.Test;

/**
 * The supplier does more than hand over the provider: it refuses a JVM where approved-only mode did not take, and picks
 * the random source. Both are checked here on their own; {@link FipsCryptoProviderTest} checks what they add up to.
 */
public class FipsCryptoProviderSupplierTest {

    /** The failure a deployment must never run with, reported with the fix in the message. */
    @Test
    public void testRequestedButNotInForceRefusesToStart() {
        IllegalStateException e =
                assertThrows(IllegalStateException.class, () -> FipsCryptoProviderSupplier.verify(true, false));

        assertThat(e.getMessage(), containsString("not in force"));
        assertThat(e.getMessage(), containsString("-D" + FipsSetup.APPROVED_ONLY_PROPERTY + "=true"));
    }

    @Test
    public void testInForceIsAccepted() {
        FipsCryptoProviderSupplier.verify(true, true);
    }

    /** Turned off on purpose is allowed, and logged; the FIPS tab reports it. */
    @Test
    public void testNotRequestedIsAccepted() {
        FipsCryptoProviderSupplier.verify(false, false);
    }

    @Test
    public void testRandomSourceIsTheFipsProviderDefault() {
        assumeTrue(FipsSetup.isFipsClasspath());
        SecureRandom random = new FipsCryptoProviderSupplier().createSecureRandom(CryptoProviders.getProvider());

        assertEquals(FipsCryptoProviderSupplier.FIPS_RANDOM_ALGORITHM, random.getAlgorithm());
        assertEquals("BCFIPS", random.getProvider().getName());
    }
}
