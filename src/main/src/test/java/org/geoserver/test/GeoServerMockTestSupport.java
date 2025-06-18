package org.geoserver.test;

import java.io.IOException;
import org.geoserver.catalog.Catalog;
import org.geoserver.data.test.MockTestData;
import org.junit.Before;

public class GeoServerMockTestSupport extends GeoServerSystemTestSupport {

    private MockTestData testData;

    @Override
    protected MockTestData createTestData() throws Exception {
        return new MockTestDataImpl();
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        testData = getTestData();
    }

    protected Catalog getCatalog() {
        return testData.getCatalog();
    }

    // Concrete implementation of MockTestData
    private static class MockTestDataImpl extends MockTestData {
        @Override
        protected void initialize() throws IOException {
            super.initialize();
        }
    }
}
