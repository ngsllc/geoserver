/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.platform.security;

import java.security.Provider;
import java.security.SecureRandom;

/**
 * Supplies the JCA provider GeoServer registers at startup, looked up through {@link java.util.ServiceLoader}.
 *
 * <p>An implementation registers itself by naming its class in
 * {@code META-INF/services/org.geoserver.platform.security.CryptoProviderSupplier}. It is loaded before Spring starts,
 * so it must not use the application context. Only the first one found is used. With none present GeoServer registers
 * the regular BouncyCastle provider. A FIPS deployment supplies one that returns the FIPS-validated provider.
 */
public interface CryptoProviderSupplier {

    /**
     * The provider to register, newly built. If the provider reads a system property while its class loads, the
     * implementation has to set that property before returning.
     */
    Provider getProvider();

    /**
     * Position to register the provider at, 1 being the most preferred. The default 0 puts it last, where the JDK
     * providers answer first and only algorithms they lack fall through to this one. Return 1 instead when this
     * provider has to be asked before the JDK, as a FIPS one does.
     *
     * @see java.security.Security#insertProviderAt(Provider, int)
     */
    default int getPosition() {
        return 0;
    }

    /**
     * Called once the provider is registered, with the instance Java will hand algorithms to, which is the one from
     * {@link #getProvider()} unless another class loader registered the same provider first.
     *
     * <p>An implementation that needs the provider in a particular state checks it here and throws when it is not:
     * GeoServer then refuses to start rather than run believing something about its cryptography that is not true. A
     * FIPS supplier uses this to make sure approved-only mode is really in force, which it is not if some other code
     * initialized the provider class before the property asking for it was set.
     *
     * @throws IllegalStateException when the provider cannot be used as registered
     */
    default void verify(Provider registered) {}

    /**
     * The source of random bytes for salts, initialization vectors and keys. The default asks the JVM for its own
     * default, which is what most deployments want. A supplier whose provider has to produce every random byte, as a
     * FIPS one does, asks its provider by name instead so that provider order can never hand the job to another one.
     *
     * @param registered the provider {@link #verify} was called with
     */
    default SecureRandom createSecureRandom(Provider registered) {
        return new SecureRandom();
    }
}
