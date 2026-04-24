/* (c) 2014 - 2016 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import java.security.SecureRandom;
import org.jasypt.iv.IvGenerator;

/**
 * A FIPS-compatible IV (Initialization Vector) generator for Jasypt.
 *
 * <p>This generator uses the system default SecureRandom implementation instead of explicitly requesting SHA1PRNG,
 * which is not available in FIPS mode. In FIPS mode, the JVM will automatically use a FIPS-approved algorithm (such as
 * DRBG).
 *
 * <p>This class replaces Jasypt's {@link org.jasypt.iv.RandomIvGenerator} which hardcodes SHA1PRNG and fails in
 * FIPS-enabled environments.
 *
 * @author GeoServer Contributors
 */
public class FipsRandomIvGenerator implements IvGenerator {

    private final SecureRandom random;

    /** Creates a new instance using the system default SecureRandom. */
    public FipsRandomIvGenerator() {
        // Use the default SecureRandom, which in FIPS mode will use a FIPS-approved algorithm
        this.random = new SecureRandom();
    }

    /**
     * Generate a random IV of the specified length in bytes.
     *
     * @param lengthBytes length in bytes.
     * @return the generated IV.
     */
    @Override
    public byte[] generateIv(final int lengthBytes) {
        final byte[] iv = new byte[lengthBytes];
        this.random.nextBytes(iv);
        return iv;
    }

    /**
     * This IV generator needs the IV to be included unencrypted in encryption results, because of its being random.
     * This method will always return true.
     *
     * @return true
     */
    @Override
    public boolean includePlainIvInEncryptionResults() {
        return true;
    }
}
