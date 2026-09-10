/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security;

import java.security.Provider;
import java.security.Security;
import java.util.Optional;
import org.geoserver.platform.ModuleStatus;

/**
 * Reports how cryptography is actually set up in this JVM, for the Modules tab of the status page. Every line is read
 * live: which provider Java hands algorithms to first, whether approved-only mode is on for the JVM and for the thread
 * rendering the page, and which provider serves random bytes. Nothing here is a constant, because a deployment that
 * asked for FIPS but did not get it is exactly what an operator needs to see.
 */
public class FIPSModuleStatus implements ModuleStatus {

    @Override
    public String getModule() {
        return "gs-main";
    }

    @Override
    public Optional<String> getComponent() {
        return Optional.of("Security");
    }

    @Override
    public String getName() {
        return "FIPS Mode";
    }

    @Override
    public Optional<String> getVersion() {
        Provider provider = Security.getProvider(KeyStoreProviderImpl.BCFIPS_PROVIDER);
        return Optional.of(provider == null ? "2.0" : provider.getName() + " " + provider.getVersionStr());
    }

    @Override
    public boolean isAvailable() {
        return true;
    }

    /** Enabled means FIPS mode is on and non-approved algorithms fail rather than run. */
    @Override
    public boolean isEnabled() {
        return FipsRuntime.isFipsMode() && FipsRuntime.isApprovedOnlyForThisThread();
    }

    @Override
    public Optional<String> getMessage() {
        boolean fipsMode = FipsRuntime.isFipsMode();
        StringBuilder msg = new StringBuilder();
        msg.append("FIPS mode: ").append(fipsMode ? "ENABLED" : "DISABLED").append('\n');
        msg.append("Approved-only mode: ")
                .append(FipsRuntime.isApprovedOnlyRequested() ? "requested" : "not requested")
                .append(", ")
                .append(
                        FipsRuntime.isApprovedOnlyForThisThread()
                                ? "in force on this thread"
                                : "NOT in force on this thread")
                .append('\n');
        msg.append("Operating system FIPS mode: ").append(describeOsFips()).append('\n');
        msg.append("Crypto provider: ")
                .append(FipsRuntime.describeProviderPosition())
                .append('\n');
        msg.append("Random source: ").append(FipsRuntime.describeRandomSource()).append('\n');
        msg.append("Keystore type: ")
                .append(KeyStoreProviderImpl.getKeyStoreType())
                .append('\n');
        if (fipsMode) {
            if (!FipsRuntime.isEnforcementEnabled()) {
                msg.append(
                        "\nEnforcement is switched off (" + FipsRuntime.ENFORCEMENT_ENV_VAR
                                + "=false): non-approved algorithms are allowed to run. This deployment is not FIPS compliant.");
            } else if (!FipsRuntime.isApprovedOnlyForThisThread()) {
                msg.append("\nApproved-only mode did not take effect on this thread. Start the JVM with -D"
                        + FipsRuntime.APPROVED_ONLY_PROPERTY + "=true.");
            } else {
                msg.append("\nPasswords are protected with AES-GCM (crypt3), keys derived with PBKDF2-HMAC-SHA256, "
                        + "secrets kept in a BCFKS keystore; all through the BouncyCastle FIPS module in approved-only "
                        + "mode.");
            }
        } else {
            msg.append("\nNon-FIPS mode uses the ")
                    .append(KeyStoreProviderImpl.getKeyStoreType())
                    .append(" keystore format with the default Java providers.");
        }
        return Optional.of(msg.toString());
    }

    private static String describeOsFips() {
        try {
            java.nio.file.Path flag = java.nio.file.Paths.get("/proc/sys/crypto/fips_enabled");
            if (java.nio.file.Files.exists(flag)) {
                return "1".equals(java.nio.file.Files.readString(flag).trim()) ? "yes" : "no";
            }
        } catch (Exception e) {
            // fall through
        }
        return "unknown";
    }

    @Override
    public Optional<String> getDocumentation() {
        return Optional.of("production/fips.html");
    }
}
