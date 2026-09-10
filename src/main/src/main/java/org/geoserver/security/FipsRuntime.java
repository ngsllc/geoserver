/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.geotools.util.logging.Logging;

/**
 * Process wide FIPS state: registration of the validated BouncyCastle provider, BouncyCastle's approved-only mode and
 * the random source GeoServer draws from.
 *
 * <p>Two facts about BC-FIPS shape everything here, both verified against bc-fips 2.1.2:
 *
 * <ul>
 *   <li>{@code org.bouncycastle.fips.approved_only} is read once, when the provider class initializes. Setting it later
 *       reaches no thread, so {@link #initialize()} has to run before anything loads a BouncyCastle class. The
 *       per-thread {@link CryptoServicesRegistrar#setApprovedOnlyMode} is not inherited by child threads and can never
 *       be undone, so it is no substitute.
 *   <li>Java hands an algorithm to the first provider offering it. Appended last, BC-FIPS would serve only the
 *       algorithms no JDK provider has, and {@code new SecureRandom()} would come from {@code SUN}. In FIPS mode the
 *       provider is therefore inserted first.
 * </ul>
 *
 * <p>In approved-only mode BC-FIPS refuses every password based cipher (the whole {@code PBEWITH*} family) and PBKDF2
 * from passwords under 112 bits. GeoServer's own algorithms stay inside that boundary; values written by earlier
 * versions are read with {@link org.geoserver.security.password.Pkcs12Pbe}, which needs only SHA-256 and AES/CBC.
 */
public final class FipsRuntime {

    private static final Logger LOGGER = Logging.getLogger("org.geoserver.security");

    /** BouncyCastle's switch: non-approved algorithms throw instead of running. Read once at provider class init. */
    public static final String APPROVED_ONLY_PROPERTY = "org.bouncycastle.fips.approved_only";

    /**
     * System property (or {@code GEOSERVER_FIPS_APPROVED_ONLY} environment variable) that turns enforcement off while
     * keeping FIPS mode. Defaults to on. A deployment running with it off is not FIPS compliant.
     */
    public static final String ENFORCEMENT_PROPERTY = "geoserver.fips.approvedOnly";

    static final String ENFORCEMENT_ENV_VAR = "GEOSERVER_FIPS_APPROVED_ONLY";

    static final String BCFIPS_PROVIDER_CLASS = "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";

    private FipsRuntime() {}

    /** FIPS mode as detected by {@link KeyStoreProviderImpl#isFipsMode()}: OS level FIPS, or {@code FIPS_MODE}. */
    public static boolean isFipsMode() {
        return KeyStoreProviderImpl.isFipsMode();
    }

    /** Whether FIPS mode should also enforce approved-only algorithms; on unless switched off explicitly. */
    public static boolean isEnforcementEnabled() {
        if (!isFipsMode()) {
            return false;
        }
        String value = System.getProperty(ENFORCEMENT_PROPERTY);
        if (value == null || value.isBlank()) {
            value = System.getenv(ENFORCEMENT_ENV_VAR);
        }
        return value == null || value.isBlank() || !"false".equalsIgnoreCase(value.trim());
    }

    /** Whether approved-only mode was requested for the JVM, by GeoServer or on the command line. */
    public static boolean isApprovedOnlyRequested() {
        return Boolean.parseBoolean(System.getProperty(APPROVED_ONLY_PROPERTY));
    }

    /** Approved-only mode of the calling thread, which is what its crypto calls are actually held to. */
    public static boolean isApprovedOnlyForThisThread() {
        try {
            return CryptoServicesRegistrar.isInApprovedOnlyMode();
        } catch (LinkageError e) {
            return false;
        }
    }

    /**
     * Servlet startup entry point, called before anything can load a BouncyCastle class. In FIPS mode with enforcement
     * enabled it requests approved-only mode, registers the provider first and then verifies the mode actually took
     * effect, failing startup when it did not: a deployment that believes it is enforcing but is not is the one outcome
     * this must never allow.
     */
    public static synchronized void initialize() {
        if (!isFipsMode()) {
            return;
        }
        boolean enforce = isEnforcementEnabled();
        if (enforce && System.getProperty(APPROVED_ONLY_PROPERTY) == null) {
            System.setProperty(APPROVED_ONLY_PROPERTY, "true");
        }
        if (!registerProvider()) {
            throw new IllegalStateException("FIPS mode is enabled but the BouncyCastle FIPS provider ("
                    + BCFIPS_PROVIDER_CLASS + ") is not on the classpath");
        }
        if (enforce) {
            if (!isApprovedOnlyForThisThread()) {
                throw new IllegalStateException(
                        "FIPS mode requires BouncyCastle approved-only mode, but the provider was "
                                + "initialized before GeoServer could request it, so the JVM is running non-approved algorithms. "
                                + "Start the JVM with -D" + APPROVED_ONLY_PROPERTY + "=true, or set "
                                + ENFORCEMENT_ENV_VAR
                                + "=false to run FIPS mode without enforcement (not a compliant deployment).");
            }
            LOGGER.info("FIPS mode: BouncyCastle approved-only mode is on, non-approved algorithms will fail");
        } else {
            LOGGER.warning("FIPS mode without approved-only enforcement (" + ENFORCEMENT_ENV_VAR
                    + "=false): non-approved algorithms are allowed to run, this deployment is not FIPS compliant");
        }
    }

    /**
     * Registers the BouncyCastle FIPS provider: first in FIPS mode, so that it serves every algorithm it offers, and
     * appended otherwise, so that a non-FIPS deployment keeps resolving to the JDK providers exactly as before.
     *
     * @return false when the provider class is not on the classpath
     */
    public static synchronized boolean registerProvider() {
        Provider existing = Security.getProvider(KeyStoreProviderImpl.BCFIPS_PROVIDER);
        if (!isFipsMode()) {
            if (existing != null) {
                return true;
            }
            Provider provider = instantiate();
            if (provider == null) {
                return false;
            }
            Security.addProvider(provider);
            LOGGER.info("Registered BouncyCastle FIPS provider at position " + Security.getProviders().length);
            return true;
        }
        if (existing != null) {
            if (Security.getProviders()[0] == existing) {
                return true;
            }
            // registered behind a JDK provider, by an earlier non-FIPS code path or another web application
            Security.removeProvider(KeyStoreProviderImpl.BCFIPS_PROVIDER);
            Security.insertProviderAt(existing, 1);
            LOGGER.info("Moved BouncyCastle FIPS provider to position 1");
            return true;
        }
        Provider provider = instantiate();
        if (provider == null) {
            return false;
        }
        int position = Security.insertProviderAt(provider, 1);
        LOGGER.info("Registered BouncyCastle FIPS provider at position " + position);
        return true;
    }

    private static Provider instantiate() {
        try {
            return Class.forName(BCFIPS_PROVIDER_CLASS)
                    .asSubclass(Provider.class)
                    .getDeclaredConstructor()
                    .newInstance();
        } catch (ClassNotFoundException e) {
            LOGGER.log(
                    isFipsMode() ? Level.SEVERE : Level.FINE,
                    "BouncyCastle FIPS provider not available in classpath. Ensure bc-fips dependency is included.");
            return null;
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.log(Level.SEVERE, "Failed to instantiate BouncyCastle FIPS provider: " + e.getMessage(), e);
            return null;
        }
    }

    /**
     * The random source for salts, IVs and keys. In FIPS mode it is the validated module's DRBG, asked for by name so
     * that provider order cannot silently hand the job to another provider; otherwise the JVM default.
     */
    public static SecureRandom secureRandom() {
        return isFipsMode() ? FipsHolder.RANDOM : DefaultHolder.RANDOM;
    }

    private static final class DefaultHolder {
        static final SecureRandom RANDOM = new SecureRandom();
    }

    private static final class FipsHolder {
        static final SecureRandom RANDOM = createFipsRandom();

        private static SecureRandom createFipsRandom() {
            registerProvider();
            try {
                return SecureRandom.getInstance("DEFAULT", KeyStoreProviderImpl.BCFIPS_PROVIDER);
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                SecureRandom random = new SecureRandom();
                LOGGER.log(
                        Level.SEVERE,
                        "FIPS mode: the BCFIPS DRBG is not available, random bytes come from "
                                + random.getProvider().getName(),
                        e);
                return random;
            }
        }
    }

    /** Name and position of the provider Java would hand an algorithm to first, for the status page. */
    public static String describeProviderPosition() {
        Provider provider = Security.getProvider(KeyStoreProviderImpl.BCFIPS_PROVIDER);
        if (provider == null) {
            return "not installed";
        }
        Provider first = Security.getProviders()[0];
        return first == provider ? "first" : "behind " + first.getName();
    }

    /** Algorithm and provider of {@link #secureRandom()}, for the status page. */
    public static String describeRandomSource() {
        SecureRandom random = secureRandom();
        return random.getAlgorithm() + " (" + random.getProvider().getName() + ")";
    }
}
