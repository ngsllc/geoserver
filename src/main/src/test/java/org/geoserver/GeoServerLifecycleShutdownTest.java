/* (c) 2023 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;

import org.junit.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ContextConfiguration;

@ContextConfiguration(classes = GeoServerLifecycleShutdownTest.TestConfig.class)
public class GeoServerLifecycleShutdownTest extends GeoServerLifecycleTestSupport {

    @Configuration
    static class TestConfig {
        @Bean
        public GeoServerLifecycleTestSupport.LifecycleWatcher lifecycleWatcher() {
            return mock(GeoServerLifecycleTestSupport.LifecycleWatcher.class);
        }
    }

    @Test
    public void testGeoServerLifecycle() throws Exception {
        assertNotNull(getGeoServer());
        getGeoServer().dispose();
    }
}
