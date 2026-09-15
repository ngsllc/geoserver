/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.fips;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.logging.Logger;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.geoserver.platform.security.CryptoProviderSupplier;
import org.geotools.util.logging.Logging;

/**
 * Selects the FIPS-validated BouncyCastle provider, in approved-only mode and ahead of the JDK providers.
 *
 * <p>If this module is on the classpath, the deployment is a FIPS one. There is no switch to turn it off, because the
 * jars it brings replace the regular BouncyCastle ones rather than sit next to them.
 *
 * <p>An installation that ended up with both sets of jars cannot work at all, so {@link #getProvider()} refuses to
 * start and its message says which jars to remove. The only place that classpath is built on purpose is
 * {@code FipsWithoutFipsJarsTest}, which checks that refusal.
 */
public class FipsCryptoProviderSupplier implements CryptoProviderSupplier {

    private static final Logger LOGGER = Logging.getLogger(FipsCryptoProviderSupplier.class);

    /** The generator BC-FIPS registers as its default: a DRBG seeded from the module's entropy source. */
    static final String FIPS_RANDOM_ALGORITHM = "DEFAULT";

    @Override
    public Provider getProvider() {
        if (!FipsSetup.isFipsClasspath()) {
            throw new IllegalStateException("The FIPS modules are installed but the regular BouncyCastle jars are on"
                    + " the classpath, where the FIPS-validated ones have to replace them. GeoServer cannot run FIPS"
                    + " this way; remove the regular jars, or remove the FIPS modules.");
        }
        // approved-only mode makes non-approved algorithms throw rather than silently run. The
        // provider reads it while its class initializes, so it has to be set before that happens.
        if (System.getProperty(FipsSetup.APPROVED_ONLY_PROPERTY) == null) {
            System.setProperty(FipsSetup.APPROVED_ONLY_PROPERTY, "true");
        }
        return new BouncyCastleFipsProvider();
    }

    @Override
    public int getPosition() {
        return 1;
    }

    /**
     * Makes sure approved-only mode is really in force when it was asked for. The provider reads the property once,
     * while its class initializes, and applies the answer to every thread: if something loaded a BouncyCastle class
     * before {@link #getProvider()} ran, another web application in the same container or an agent for instance, the
     * property came too late and the JVM is running non-approved algorithms while reporting that it does not. That is
     * the one outcome a FIPS deployment must never have, so it fails to start instead, naming the fix.
     */
    @Override
    public void verify(Provider registered) {
        verify(FipsSetup.isApprovedOnlyRequested(), FipsSetup.isApprovedOnlyForThisThread());
    }

    static void verify(boolean requested, boolean inForce) {
        if (requested && !inForce) {
            throw new IllegalStateException("BouncyCastle approved-only mode was requested but is not in force: the"
                    + " FIPS provider class was initialized before GeoServer could ask for it, so this JVM would run"
                    + " non-approved algorithms. Start the JVM with -D" + FipsSetup.APPROVED_ONLY_PROPERTY
                    + "=true so the setting is there from the start.");
        }
        if (!requested) {
            LOGGER.warning("BouncyCastle approved-only mode is off (-D" + FipsSetup.APPROVED_ONLY_PROPERTY
                    + "=false): non-approved algorithms are allowed to run, this deployment is not FIPS compliant");
        }
    }

    /**
     * The validated module's own generator, asked for by name and provider. Left to the JVM default it is the same
     * generator as long as the provider stays first, which nothing guarantees for the life of the JVM.
     */
    @Override
    public SecureRandom createSecureRandom(Provider registered) {
        try {
            return SecureRandom.getInstance(FIPS_RANDOM_ALGORITHM, registered);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(
                    "The FIPS provider " + registered.getName() + " offers no " + FIPS_RANDOM_ALGORITHM
                            + " random number generator, GeoServer cannot draw random bytes from the validated module",
                    e);
        }
    }
}
