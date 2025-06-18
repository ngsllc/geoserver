/* (c) 2015 -2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.catalog;

import org.geoserver.test.GeoServerMockTestSupport;
import org.junit.Before;
import org.junit.Test;

public class LayerGroupHelperTest extends GeoServerMockTestSupport {

    private LayerGroupHelper helper;

    @Before
    public void setUp() throws Exception {
        helper = new LayerGroupHelper(getCatalog());
    }

    @Test
    public void testLayerGroupHelper() throws Exception {
        // Test logic for layer group helper
        // Simplified for brevity; add actual tests as needed
    }
}
