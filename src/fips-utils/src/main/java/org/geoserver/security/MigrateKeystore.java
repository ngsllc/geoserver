package org.geoserver.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.util.Enumeration;
import org.apache.commons.cli.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Standalone keystore migration utility for FIPS compliance. This utility can migrate keystores between different
 * formats and providers.
 */
public class MigrateKeystore {

    private static final Logger logger = LoggerFactory.getLogger(MigrateKeystore.class);

    // Static initialization to register BouncyCastle provider
    static {
        try {
            // Register BouncyCastle provider if not already registered
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                logger.info("BouncyCastle provider registered successfully");
            }
        } catch (Exception e) {
            logger.warn("Could not register BouncyCastle provider: " + e.getMessage());
        }
    }

    /** Main method for keystore migration */
    public static void main(String[] args) {
        Options options = new Options();

        options.addOption("s", "source", true, "Source keystore file (required)");
        options.addOption("sp", "source-password", true, "Source keystore password (required)");
        options.addOption("t", "target", true, "Target keystore file (required)");
        options.addOption("tp", "target-password", true, "Target keystore password (required)");
        options.addOption("st", "source-type", true, "Source keystore type (default: auto-detect)");
        options.addOption("sp", "source-provider", true, "Source keystore provider (default: auto-detect)");
        options.addOption("tt", "target-type", true, "Target keystore type (default: BCFKS)");
        options.addOption("tp", "target-provider", true, "Target keystore provider (default: auto-detect)");
        options.addOption("v", "verbose", false, "Verbose output");
        options.addOption("h", "help", false, "Show help");

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

        try {
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("help")) {
                formatter.printHelp("MigrateKeystore", options);
                return;
            }

            // Validate required arguments
            String sourceFile = cmd.getOptionValue("source");
            String sourcePassword = cmd.getOptionValue("source-password");
            String targetFile = cmd.getOptionValue("target");
            String targetPassword = cmd.getOptionValue("target-password");

            if (sourceFile == null || sourcePassword == null || targetFile == null || targetPassword == null) {
                System.err.println("Error: source, source-password, target, and target-password are required");
                formatter.printHelp("MigrateKeystore", options);
                return;
            }

            // Get optional arguments
            String sourceType = cmd.getOptionValue("source-type");
            String sourceProvider = cmd.getOptionValue("source-provider");
            String targetType = cmd.getOptionValue("target-type", "BCFKS");
            String targetProvider = cmd.getOptionValue("target-provider");
            boolean verbose = cmd.hasOption("verbose");

            // Perform migration
            migrateKeystore(
                    sourceFile,
                    sourcePassword,
                    sourceType,
                    sourceProvider,
                    targetFile,
                    targetPassword,
                    targetType,
                    targetProvider,
                    verbose);

        } catch (ParseException e) {
            System.err.println("Error parsing arguments: " + e.getMessage());
            formatter.printHelp("MigrateKeystore", options);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /** Migrate a keystore from one format to another */
    public static void migrateKeystore(
            String sourceFile,
            String sourcePassword,
            String sourceType,
            String sourceProvider,
            String targetFile,
            String targetPassword,
            String targetType,
            String targetProvider,
            boolean verbose) {

        System.out.println("=== Keystore Migration ===");
        System.out.println("Source: " + sourceFile + " (" + sourceType + "/" + sourceProvider + ")");
        System.out.println("Target: " + targetFile + " (" + targetType + "/" + targetProvider + ")");

        try {
            // Validate source file
            File source = new File(sourceFile);
            if (!source.exists()) {
                throw new IllegalArgumentException("Source keystore file does not exist: " + sourceFile);
            }

            // Auto-detect source type if not specified
            if (sourceType == null) {
                sourceType = detectKeystoreType(sourceFile);
                System.out.println("Auto-detected source type: " + sourceType);
            }

            // Auto-detect source provider if not specified
            if (sourceProvider == null) {
                sourceProvider = detectKeystoreProvider(sourceType);
                System.out.println("Auto-detected source provider: " + sourceProvider);
            }

            // Auto-detect target provider if not specified
            if (targetProvider == null) {
                targetProvider = detectKeystoreProvider(targetType);
                System.out.println("Auto-detected target provider: " + targetProvider);
            }

            // Load source keystore
            KeyStore sourceKeystore;
            if (sourceProvider != null) {
                sourceKeystore = KeyStore.getInstance(sourceType, sourceProvider);
            } else {
                sourceKeystore = KeyStore.getInstance(sourceType);
            }

            try (FileInputStream fis = new FileInputStream(source)) {
                sourceKeystore.load(fis, sourcePassword.toCharArray());
            }

            System.out.println("✓ Source keystore loaded successfully");

            if (verbose) {
                System.out.println("Source keystore entries:");
                Enumeration<String> aliases = sourceKeystore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (sourceKeystore.isCertificateEntry(alias)) {
                        System.out.println("  Certificate: " + alias);
                    } else if (sourceKeystore.isKeyEntry(alias)) {
                        System.out.println("  Key: " + alias);
                    }
                }
            }

            // Create target keystore
            KeyStore targetKeystore;
            if (targetProvider != null) {
                targetKeystore = KeyStore.getInstance(targetType, targetProvider);
            } else {
                targetKeystore = KeyStore.getInstance(targetType);
            }

            targetKeystore.load(null, targetPassword.toCharArray());

            // Copy entries
            Enumeration<String> aliases = sourceKeystore.aliases();
            int certificateCount = 0;
            int keyCount = 0;

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();

                if (sourceKeystore.isCertificateEntry(alias)) {
                    targetKeystore.setCertificateEntry(alias, sourceKeystore.getCertificate(alias));
                    certificateCount++;
                    if (verbose) {
                        System.out.println("  Migrated certificate: " + alias);
                    }
                } else if (sourceKeystore.isKeyEntry(alias)) {
                    targetKeystore.setKeyEntry(
                            alias,
                            sourceKeystore.getKey(alias, sourcePassword.toCharArray()),
                            targetPassword.toCharArray(),
                            sourceKeystore.getCertificateChain(alias));
                    keyCount++;
                    if (verbose) {
                        System.out.println("  Migrated key: " + alias);
                    }
                }
            }

            // Save target keystore
            try (FileOutputStream fos = new FileOutputStream(targetFile)) {
                targetKeystore.store(fos, targetPassword.toCharArray());
            }

            System.out.println("✓ Migration completed successfully");
            System.out.println("  Certificates migrated: " + certificateCount);
            System.out.println("  Keys migrated: " + keyCount);
            System.out.println("  Total entries: " + (certificateCount + keyCount));

        } catch (Exception e) {
            System.err.println("✗ Migration failed: " + e.getMessage());
            throw new RuntimeException("Keystore migration failed", e);
        }
    }

    /** Auto-detect keystore type based on file extension */
    private static String detectKeystoreType(String filename) {
        String lower = filename.toLowerCase();
        if (lower.endsWith(".p12") || lower.endsWith(".pfx")) {
            return "PKCS12";
        } else if (lower.endsWith(".jks")) {
            return "JKS";
        } else if (lower.endsWith(".bcfks")) {
            return "BCFKS";
        } else {
            return "JCEKS"; // Default
        }
    }

    /** Auto-detect keystore provider based on type */
    private static String detectKeystoreProvider(String keystoreType) {
        if ("BCFKS".equals(keystoreType)) {
            // Try to find available BouncyCastle provider
            if (Security.getProvider("BCFIPS") != null) {
                return "BCFIPS";
            } else if (Security.getProvider("BC") != null) {
                return "BC";
            } else {
                throw new IllegalStateException("No BouncyCastle provider available for BCFKS keystore");
            }
        }
        return null; // Use default provider
    }
}
