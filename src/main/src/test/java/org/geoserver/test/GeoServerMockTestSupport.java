package org.geoserver.test;

import java.io.IOException;
import org.geoserver.catalog.Catalog;
import org.geoserver.data.test.SystemTestData;
import org.junit.Before;

public class GeoServerMockTestSupport extends GeoServerSystemTestSupport {

    private MockSystemTestData testData;

    @Override
    protected SystemTestData createTestData() throws Exception {
        return new MockSystemTestData();
    }

    @Before
    public void setUp() throws Exception {
        testData = (MockSystemTestData) getTestData();
        super.setUp(testData);
    }

    protected Catalog getCatalog() {
        return super.getCatalog();
    }

    // Mock implementation of SystemTestData for testing
    private static class MockSystemTestData extends SystemTestData {

        public MockSystemTestData() throws IOException {
            super();
        }

        @Override
        public void setUp() throws Exception {
            // Minimal setup for mock testing
            createCatalog();
            createConfig();
        }

        @Override
        protected void createCatalog() throws IOException {
            // Create a minimal catalog for testing
            super.createCatalog();
        }
    }
}
