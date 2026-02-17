/* (c) 2014 - 2016 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.web;

import java.security.SecureRandom;
import org.apache.wicket.core.random.ISecureRandomSupplier;

/**
 * A FIPS-compatible SecureRandom supplier for Wicket.
 *
 * <p>This supplier uses the system default SecureRandom implementation instead of explicitly requesting SHA1PRNG, which
 * is not available in FIPS mode. In FIPS mode, the JVM will automatically use a FIPS-approved algorithm (such as DRBG).
 *
 * @author GeoServer Contributors
 */
public class FipsSecureRandomSupplier implements ISecureRandomSupplier {

    private static final SecureRandom INSTANCE = new SecureRandom();

    @Override
    public SecureRandom getRandom() {
        // Use the default SecureRandom, which in FIPS mode will use a FIPS-approved algorithm
        return INSTANCE;
    }
}
