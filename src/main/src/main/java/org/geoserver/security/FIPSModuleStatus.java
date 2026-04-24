/* (c) 2025 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security;

import java.util.Optional;
import org.geoserver.platform.ModuleStatus;

/**
 * Report FIPS mode status and keystore configuration.
 *
 * @author GeoServer Team
 */
public class FIPSModuleStatus implements ModuleStatus {

    @Override
    public String getModule() {
        return "gs-main";
    }

    @Override
    public Category getCategory() {
        return Category.CORE;
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
        return Optional.of("1.0");
    }

    @Override
    public boolean isAvailable() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return KeyStoreProviderImpl.isFipsMode();
    }

    @Override
    public Optional<String> getMessage() {
        StringBuilder msg = new StringBuilder();

        boolean fipsMode = KeyStoreProviderImpl.isFipsMode();
        String keystoreType = KeyStoreProviderImpl.getKeyStoreType();

        msg.append("FIPS Mode: ").append(fipsMode ? "ENABLED" : "DISABLED").append("\n");
        msg.append("Keystore Type: ").append(keystoreType).append("\n");

        if (fipsMode) {
            msg.append("Provider: BCFIPS (BouncyCastle FIPS)\n");
            msg.append("\nFIPS mode enables Federal Information Processing Standards compliant ");
            msg.append("cryptographic operations using BCFKS keystore format.");
        } else {
            msg.append("Provider: Default (JCE)\n");
            msg.append("\nNon-FIPS mode uses the ")
                    .append(keystoreType)
                    .append(" keystore format with default Java providers.");
        }

        return Optional.of(msg.toString());
    }

    @Override
    public Optional<String> getDocumentation() {
        return Optional.of("production/fips.html");
    }
}
