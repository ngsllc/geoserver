/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.web;

import java.security.SecureRandom;
import org.apache.wicket.core.random.ISecureRandomSupplier;
import org.geoserver.security.FipsRuntime;

/**
 * Wicket's random source, taken from {@link FipsRuntime#secureRandom()}: the validated module's DRBG in FIPS mode,
 * asked for by name so that provider order cannot hand the job to another provider, and the JVM default otherwise.
 * Wicket's own supplier asks for {@code SHA1PRNG} by name, which no FIPS provider offers.
 */
public class FipsSecureRandomSupplier implements ISecureRandomSupplier {

    @Override
    public SecureRandom getRandom() {
        return FipsRuntime.secureRandom();
    }
}
