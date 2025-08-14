/* (c) 2014 - 2016 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.web;

import java.lang.reflect.Field;
import org.apache.wicket.authorization.IAuthorizationStrategy;
import org.apache.wicket.authorization.UnauthorizedInstantiationException;
import org.apache.wicket.coep.CrossOriginEmbedderPolicyConfiguration;
import org.apache.wicket.coop.CrossOriginOpenerPolicyConfiguration;
import org.apache.wicket.settings.DefaultUnauthorizedResourceRequestListener;
import org.apache.wicket.settings.SecuritySettings;

/**
 * A FIPS-compatible SecuritySettings that avoids the SHA1PRNG issue in Wicket 9.22.0.
 *
 * <p>Wicket 9.22.0's SecuritySettings constructor eagerly creates a DefaultSecureRandomSupplier which uses SHA1PRNG -
 * an algorithm not available in FIPS mode. This class works around the issue by using Unsafe to instantiate
 * SecuritySettings without calling its constructor, then manually initializing all required fields.
 *
 * <p>This workaround can be removed once GeoServer upgrades to Wicket 9.23.0+ which includes the fix for WICKET-7174.
 *
 * @author GeoServer Contributors
 */
public class FipsSecuritySettings {

    /**
     * Creates a FIPS-compatible SecuritySettings by using Unsafe to bypass the constructor and manually initializing
     * all required fields.
     *
     * @return a SecuritySettings configured for FIPS mode
     */
    public static SecuritySettings createForFipsMode() {
        try {
            // Use Unsafe to create instance without calling constructor (which fails in FIPS mode)
            SecuritySettings settings = instantiateWithoutConstructor(SecuritySettings.class);

            // Initialize all fields that would normally be set by the constructor or field initializers
            // These mirror the default values from SecuritySettings source code
            settings.setRandomSupplier(new FipsSecureRandomSupplier());
            settings.setAuthorizationStrategy(IAuthorizationStrategy.ALLOW_ALL);
            settings.setUnauthorizedComponentInstantiationListener(component -> {
                throw new UnauthorizedInstantiationException(component.getClass());
            });

            // Set the default unauthorized resource request listener
            settings.setUnauthorizedResourceRequestListener(new DefaultUnauthorizedResourceRequestListener());

            // Initialize COOP and COEP configurations with defaults (disabled)
            settings.setCrossOriginOpenerPolicyConfiguration(CrossOriginOpenerPolicyConfiguration.CoopMode.DISABLED);
            settings.setCrossOriginEmbedderPolicyConfiguration(
                    CrossOriginEmbedderPolicyConfiguration.CoepMode.DISABLED);

            return settings;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create FIPS-compatible SecuritySettings", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T instantiateWithoutConstructor(Class<T> clazz) throws Exception {
        // Use sun.misc.Unsafe to create instance without calling constructor
        Field unsafeField = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
        unsafeField.setAccessible(true);
        sun.misc.Unsafe unsafe = (sun.misc.Unsafe) unsafeField.get(null);
        return (T) unsafe.allocateInstance(clazz);
    }
}
