package org.geoserver.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;
import org.apache.commons.cli.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FIPS-compliant keystore provider with standalone testing capabilities. This class can be used both as a library and
 * as a standalone utility.
 */
public class FIPSKeyStoreProvider {

    private static final Logger logger = LoggerFactory.getLogger(FIPSKeyStoreProvider.class);

    // Environment variables
    public static final String FIPS_MODE_ENV_VAR = "FIPS_MODE";
    public static final String KEYSTORE_TYPE_ENV_VAR = "GEOSERVER_KEYSTORE_TYPE";
    public static final String KEYSTORE_PROVIDER_ENV_VAR = "GEOSERVER_KEYSTORE_PROVIDER";

    // Default values
    public static final String DEFAULT_KEYSTORE_TYPE = "JCEKS";
    public static final String BCFKS_KEYSTORE_TYPE = "BCFKS";
    public static final String BCFIPS_PROVIDER = "BCFIPS";
    public static final String BC_PROVIDER = "BC";

    // Static initialization to register BouncyCastle provider
    static {
        try {
            // Register BouncyCastle provider if not already registered
            if (Security.getProvider(BC_PROVIDER) == null) {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                logger.info("BouncyCastle provider registered successfully");
            }
        } catch (Exception e) {
            logger.warn("Could not register BouncyCastle provider: " + e.getMessage());
        }
    }

    /** Main method for standalone testing and utility operations */
    public static void main(String[] args) {
        Options options = new Options();

        options.addOption("d", "detect", false, "Detect FIPS mode and available providers");
        options.addOption("t", "test", false, "Test keystore operations");
        options.addOption("m", "migrate", false, "Migrate keystore");
        options.addOption("s", "source", true, "Source keystore file");
        options.addOption("p", "password", true, "Keystore password");
        options.addOption("o", "output", true, "Output keystore file");
        options.addOption("h", "help", false, "Show help");

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

        try {
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("help")) {
                formatter.printHelp("FIPSKeyStoreProvider", options);
                return;
            }

            if (cmd.hasOption("detect")) {
                detectFIPSMode();
                return;
            }

            if (cmd.hasOption("test")) {
                testKeystoreOperations();
                return;
            }

            if (cmd.hasOption("migrate")) {
                String source = cmd.getOptionValue("source");
                String password = cmd.getOptionValue("password");
                String output = cmd.getOptionValue("output");

                if (source == null || password == null || output == null) {
                    System.err.println("Error: source, password, and output are required for migration");
                    formatter.printHelp("FIPSKeyStoreProvider", options);
                    return;
                }

                migrateKeystore(source, password, output);
                return;
            }

            // Default: just detect FIPS mode
            detectFIPSMode();

        } catch (ParseException e) {
            System.err.println("Error parsing arguments: " + e.getMessage());
            formatter.printHelp("FIPSKeyStoreProvider", options);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /** Detect and display FIPS mode status */
    public static void detectFIPSMode() {
        System.out.println("=== FIPS Mode Detection ===");

        // Check FIPS mode
        boolean fipsMode = isFIPSModeEnabled();
        System.out.println("FIPS mode detected: " + fipsMode);

        if (fipsMode) {
            System.out.println("✓ FIPS mode is active");
        } else {
            System.out.println("⚠ FIPS mode is not active");
        }

        // Check environment variables
        System.out.println("\nEnvironment Variables:");
        System.out.println("FIPS_MODE: " + System.getenv(FIPS_MODE_ENV_VAR));
        System.out.println("GEOSERVER_KEYSTORE_TYPE: " + System.getenv(KEYSTORE_TYPE_ENV_VAR));
        System.out.println("GEOSERVER_KEYSTORE_PROVIDER: " + System.getenv(KEYSTORE_PROVIDER_ENV_VAR));

        // List available security providers
        System.out.println("\nAvailable Security Providers:");
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            System.out.println("  " + p.getName() + " (v" + p.getVersion() + ")");
        }

        // Check specific providers
        System.out.println("\nProvider Status:");
        System.out.println(
                "BCFIPS: " + (Security.getProvider(BCFIPS_PROVIDER) != null ? "✓ Available" : "✗ Not available"));
        System.out.println("BC: " + (Security.getProvider(BC_PROVIDER) != null ? "✓ Available" : "✗ Not available"));

        // Test keystore types
        System.out.println("\nKeystore Type Support:");
        testKeystoreType("JCEKS");
        testKeystoreType("PKCS12");
        testKeystoreType("BCFKS");
    }

    /** Test basic keystore operations */
    public static void testKeystoreOperations() {
        System.out.println("=== Keystore Operations Test ===");

        try {
            // Test BCFKS keystore creation
            String provider = getKeyStoreProviderForType(BCFKS_KEYSTORE_TYPE);
            System.out.println("Using provider for BCFKS: " + provider);

            KeyStore keystore = KeyStore.getInstance(BCFKS_KEYSTORE_TYPE, provider);
            keystore.load(null, "testpass".toCharArray());

            System.out.println("✓ BCFKS keystore created successfully");

            // Test JCEKS keystore creation
            KeyStore jceksKeystore = KeyStore.getInstance("JCEKS");
            jceksKeystore.load(null, "testpass".toCharArray());

            System.out.println("✓ JCEKS keystore created successfully");

        } catch (Exception e) {
            System.err.println("✗ Keystore test failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /** Migrate a keystore to FIPS-compliant format */
    public static void migrateKeystore(String sourcePath, String password, String outputPath) {
        System.out.println("=== Keystore Migration ===");
        System.out.println("Source: " + sourcePath);
        System.out.println("Output: " + outputPath);

        try {
            File sourceFile = new File(sourcePath);
            if (!sourceFile.exists()) {
                throw new IllegalArgumentException("Source keystore file does not exist: " + sourcePath);
            }

            // Load source keystore
            KeyStore sourceKeystore = KeyStore.getInstance("JCEKS");
            try (FileInputStream fis = new FileInputStream(sourceFile)) {
                sourceKeystore.load(fis, password.toCharArray());
            }

            System.out.println("✓ Source keystore loaded successfully");

            // Create target keystore
            String provider = getKeyStoreProviderForType(BCFKS_KEYSTORE_TYPE);
            KeyStore targetKeystore = KeyStore.getInstance(BCFKS_KEYSTORE_TYPE, provider);
            targetKeystore.load(null, password.toCharArray());

            // Copy entries
            Enumeration<String> aliases = sourceKeystore.aliases();
            int count = 0;
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (sourceKeystore.isCertificateEntry(alias)) {
                    targetKeystore.setCertificateEntry(alias, sourceKeystore.getCertificate(alias));
                } else if (sourceKeystore.isKeyEntry(alias)) {
                    targetKeystore.setKeyEntry(
                            alias,
                            sourceKeystore.getKey(alias, password.toCharArray()),
                            password.toCharArray(),
                            sourceKeystore.getCertificateChain(alias));
                }
                count++;
            }

            // Save target keystore
            try (FileOutputStream fos = new FileOutputStream(outputPath)) {
                targetKeystore.store(fos, password.toCharArray());
            }

            System.out.println("✓ Migration completed successfully");
            System.out.println("  Entries migrated: " + count);

        } catch (Exception e) {
            System.err.println("✗ Migration failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /** Check if FIPS mode is enabled */
    public static boolean isFIPSModeEnabled() {
        // Check environment variable
        String fipsMode = System.getenv(FIPS_MODE_ENV_VAR);
        if (fipsMode != null && !fipsMode.trim().isEmpty()) {
            return Boolean.parseBoolean(fipsMode.trim());
        }

        // Check system property
        String fipsProperty = System.getProperty("com.redhat.fips");
        if (fipsProperty != null) {
            return Boolean.parseBoolean(fipsProperty);
        }

        // Check if BouncyCastle FIPS provider is available
        return Security.getProvider(BCFIPS_PROVIDER) != null || Security.getProvider(BC_PROVIDER) != null;
    }

    /** Gets the appropriate provider for a specific keystore type */
    public static String getKeyStoreProviderForType(String keystoreType) {
        // Check environment variable first
        String envProvider = System.getenv(KEYSTORE_PROVIDER_ENV_VAR);
        if (envProvider != null && !envProvider.trim().isEmpty()) {
            return envProvider.trim();
        }

        if (BCFKS_KEYSTORE_TYPE.equals(keystoreType)) {
            // Try to find available BouncyCastle provider
            if (Security.getProvider(BCFIPS_PROVIDER) != null) {
                return BCFIPS_PROVIDER;
            } else if (Security.getProvider(BC_PROVIDER) != null) {
                return BC_PROVIDER;
            } else {
                throw new IllegalStateException("No BouncyCastle provider available for BCFKS keystore");
            }
        }

        return null; // Use default provider
    }

    /** Test if a keystore type is supported */
    private static void testKeystoreType(String keystoreType) {
        try {
            if (BCFKS_KEYSTORE_TYPE.equals(keystoreType)) {
                String provider = getKeyStoreProviderForType(keystoreType);
                KeyStore.getInstance(keystoreType, provider);
                System.out.println("  " + keystoreType + ": ✓ Supported (provider: " + provider + ")");
            } else {
                KeyStore.getInstance(keystoreType);
                System.out.println("  " + keystoreType + ": ✓ Supported");
            }
        } catch (Exception e) {
            System.out.println("  " + keystoreType + ": ✗ Not supported (" + e.getMessage() + ")");
        }
    }
}
