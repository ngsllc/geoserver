package org.geoserver.data.test;

import java.io.File;
import java.io.IOException;
import org.apache.commons.io.FileUtils;
import org.geoserver.catalog.Catalog;
import org.geoserver.catalog.DataStoreInfo;
import org.geoserver.catalog.FeatureTypeInfo;
import org.geoserver.catalog.LayerInfo;
import org.geoserver.catalog.NamespaceInfo;
import org.geoserver.catalog.WorkspaceInfo;
import org.geotools.api.feature.simple.SimpleFeatureType;
import org.geotools.feature.simple.SimpleFeatureTypeBuilder;
import org.junit.After;
import org.junit.Before;

public abstract class MockTestData {

    protected File dataDir;
    protected Catalog catalog;

    @Before
    public void setUp() throws IOException {
        dataDir = File.createTempFile("geoserver", "data");
        dataDir.delete();
        dataDir.mkdir();
        catalog = MockCreator.createCatalog(dataDir);
        initialize();
    }

    @After
    public void tearDown() throws IOException {
        FileUtils.deleteDirectory(dataDir);
        catalog = null;
    }

    protected void initialize() throws IOException {
        // Create a workspace and namespace
        WorkspaceInfo ws = MockCreator.createWorkspace(catalog, "test", "http://test.org");
        catalog.add(ws);
        NamespaceInfo ns = catalog.getNamespaceByPrefix("test");
        catalog.add(ns);

        // Create a data store
        DataStoreInfo ds = MockCreator.createDataStore("testStore", ws);
        catalog.add(ds);

        // Create a feature type
        SimpleFeatureTypeBuilder builder = new SimpleFeatureTypeBuilder();
        builder.setName("testFeatureType");
        builder.setNamespaceURI("http://test.org");
        builder.add("name", String.class);
        SimpleFeatureType ft = builder.buildFeatureType();
        FeatureTypeInfo ftInfo = MockCreator.createFeatureType("testFeatureType", ds, ns, ft);
        catalog.add(ftInfo);

        // Create a layer
        LayerInfo layer = MockCreator.createLayer(ftInfo);
        catalog.add(layer);
    }

    public Catalog getCatalog() {
        return catalog;
    }

    public File getDataDir() {
        return dataDir;
    }
}
