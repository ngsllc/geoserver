/*
 * Copyright (c) 2024 Open Source Geospatial Foundation (OSGeo)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.geoserver.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public class KeyStoreProviderImplTest {

    @Test
    public void testGetKeyStoreTypeDefault() {
        // Test default behavior when environment variable is not set
        // Note: We can't easily set environment variables in tests, so we test the default
        String keystoreType = KeyStoreProviderImpl.getKeyStoreType();
        assertEquals("JCEKS", keystoreType);
    }

    @Test
    public void testGetKeyStoreProviderForBCFKS() {
        // Test that BCFKS returns the correct provider
        // This test verifies the logic works correctly
        String provider = KeyStoreProviderImpl.getKeyStoreProvider();
        // The actual provider depends on the environment variable, but we can test the logic
        // by checking that if the type is BCFKS, it returns BCFIPS
        if ("BCFKS".equals(KeyStoreProviderImpl.getKeyStoreType())) {
            assertEquals("BCFIPS", provider);
        } else {
            assertNull(provider);
        }
    }

    @Test
    public void testGetKeyStoreProviderLogic() {
        // Test the provider selection logic
        // For BCFKS, should return BC (since BCFIPS provider is not registered in test environment)
        assertEquals("BC", KeyStoreProviderImpl.getKeyStoreProviderForType("BCFKS"));

        // For JCEKS, should return null (default provider)
        assertNull(KeyStoreProviderImpl.getKeyStoreProviderForType("JCEKS"));

        // For other types, should return null (default provider)
        assertNull(KeyStoreProviderImpl.getKeyStoreProviderForType("PKCS12"));
        assertNull(KeyStoreProviderImpl.getKeyStoreProviderForType("JKS"));
    }

    @Test
    public void testFileNames() {
        // Test that file names are generated correctly based on keystore type
        KeyStoreProviderImpl provider = new KeyStoreProviderImpl();

        // The actual file names depend on the environment variable
        String keystoreType = KeyStoreProviderImpl.getKeyStoreType();
        String expectedExtension = keystoreType.toLowerCase();

        assertEquals("geoserver." + expectedExtension, provider.getDefaultFileName());
        assertEquals("geoserver." + expectedExtension + ".new", provider.getPreparedFileName());
    }

    @Test
    public void testEnvironmentVariableConstants() {
        // Test that the constants are defined correctly
        assertEquals("GEOSERVER_KEYSTORE_TYPE", KeyStoreProviderImpl.KEYSTORE_TYPE_ENV_VAR);
        assertEquals("JCEKS", KeyStoreProviderImpl.DEFAULT_KEYSTORE_TYPE);
        assertEquals("BCFKS", KeyStoreProviderImpl.BCFKS_KEYSTORE_TYPE);
        assertEquals("BCFIPS", KeyStoreProviderImpl.BCFIPS_PROVIDER);
    }

    @Test
    public void testEnvironmentVariableBehavior() {
        // Test that the environment variable logic works correctly
        // This test documents the expected behavior without actually setting env vars

        // When environment variable is not set, should return default
        String keystoreType = KeyStoreProviderImpl.getKeyStoreType();
        assertEquals("JCEKS", keystoreType);

        // The provider should be null for JCEKS (default provider)
        String provider = KeyStoreProviderImpl.getKeyStoreProvider();
        assertNull(provider);
    }
}
