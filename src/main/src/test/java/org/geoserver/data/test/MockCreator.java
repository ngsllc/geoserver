package org.geoserver.data.test;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletContext;
import org.easymock.EasyMock;
import org.geoserver.catalog.Catalog;
import org.geoserver.catalog.CoverageInfo;
import org.geoserver.catalog.CoverageStoreInfo;
import org.geoserver.catalog.DataStoreInfo;
import org.geoserver.catalog.FeatureTypeInfo;
import org.geoserver.catalog.LayerGroupInfo;
import org.geoserver.catalog.LayerInfo;
import org.geoserver.catalog.NamespaceInfo;
import org.geoserver.catalog.PublishedInfo;
import org.geoserver.catalog.ResourceInfo;
import org.geoserver.catalog.StyleInfo;
import org.geoserver.catalog.WorkspaceInfo;
import org.geoserver.catalog.impl.CatalogImpl;
import org.geoserver.config.ConfigurationListener;
import org.geoserver.config.GeoServer;
import org.geoserver.config.GeoServerInfo;
import org.geoserver.config.LoggingInfo;
import org.geoserver.config.SettingsInfo;
import org.geoserver.platform.GeoServerResourceLoader;
import org.geoserver.security.password.GeoServerPBEPasswordEncoder;
import org.geotools.api.feature.simple.SimpleFeatureType;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

public class MockCreator {
    private MockCreator() {}

    public static Catalog createCatalog(File dataDir) {
        CatalogImpl catalog = new CatalogImpl();
        GeoServerResourceLoader resourceLoader = createResourceLoader(dataDir);
        catalog.setResourceLoader(resourceLoader);
        return catalog;
    }

    public static GeoServerResourceLoader createResourceLoader(File dataDir) {
        return new GeoServerResourceLoader(dataDir);
    }

    public static ServletContext createServletContext(File dataDir) {
        ServletContext servletContext = createNiceMock(ServletContext.class);
        expect(servletContext.getInitParameter("GEOSERVER_DATA_DIR")).andReturn(dataDir.getPath());
        expect(servletContext.getRealPath(anyObject(String.class)))
                .andAnswer(() -> new File(dataDir, (String) EasyMock.getCurrentArguments()[0]).getPath())
                .anyTimes();
        replay(servletContext);
        return servletContext;
    }

    public static ApplicationContext createApplicationContext() {
        ApplicationContext applicationContext = createNiceMock(ApplicationContext.class);
        expect(applicationContext.getBeanNamesForType(GeoServer.class))
                .andReturn(new String[] {"geoServer"})
                .anyTimes();
        GeoServer geoServer = createGeoServer();
        expect(applicationContext.getBean("geoServer")).andReturn(geoServer).anyTimes();
        replay(applicationContext);
        return applicationContext;
    }

    public static GeoServer createGeoServer() {
        GeoServer geoServer = createNiceMock(GeoServer.class);
        GeoServerInfo global = createGeoServerInfo();
        expect(geoServer.getGlobal()).andReturn(global).anyTimes();
        SettingsInfo settings = createSettingsInfo();
        expect(geoServer.getSettings()).andReturn(settings).anyTimes();
        LoggingInfo logging = createLoggingInfo();
        expect(geoServer.getLogging()).andReturn(logging).anyTimes();
        Catalog catalog = createCatalog();
        expect(geoServer.getCatalog()).andReturn(catalog).anyTimes();
        expect(geoServer.getListeners())
                .andReturn(new ArrayList<ConfigurationListener>())
                .anyTimes();
        replay(geoServer);
        return geoServer;
    }

    public static GeoServerInfo createGeoServerInfo() {
        GeoServerInfo geoServerInfo = createNiceMock(GeoServerInfo.class);
        replay(geoServerInfo);
        return geoServerInfo;
    }

    public static SettingsInfo createSettingsInfo() {
        SettingsInfo settingsInfo = createNiceMock(SettingsInfo.class);
        replay(settingsInfo);
        return settingsInfo;
    }

    public static LoggingInfo createLoggingInfo() {
        LoggingInfo loggingInfo = createNiceMock(LoggingInfo.class);
        replay(loggingInfo);
        return loggingInfo;
    }

    public static Catalog createCatalog() {
        Catalog catalog = createNiceMock(Catalog.class);
        replay(catalog);
        return catalog;
    }

    public static WorkspaceInfo createWorkspace(Catalog catalog, String name, String uri) {
        WorkspaceInfo ws = createNiceMock(WorkspaceInfo.class);
        expect(ws.getName()).andReturn(name).anyTimes();
        NamespaceInfo ns = createNamespace(catalog, name, uri);
        expect(catalog.getNamespaceByPrefix(name)).andReturn(ns).anyTimes();
        replay(ws);
        return ws;
    }

    public static NamespaceInfo createNamespace(Catalog catalog, String name, String uri) {
        NamespaceInfo ns = createNiceMock(NamespaceInfo.class);
        expect(ns.getName()).andReturn(name).anyTimes();
        expect(ns.getURI()).andReturn(uri).anyTimes();
        expect(ns.getPrefix()).andReturn(name).anyTimes();
        expect(catalog.getNamespaceByPrefix(name)).andReturn(ns).anyTimes();
        replay(ns);
        return ns;
    }

    public static DataStoreInfo createDataStore(String name, WorkspaceInfo ws) {
        DataStoreInfo ds = createNiceMock(DataStoreInfo.class);
        expect(ds.getName()).andReturn(name).anyTimes();
        expect(ds.getWorkspace()).andReturn(ws).anyTimes();
        expect(ds.isEnabled()).andReturn(true).anyTimes();
        replay(ds);
        return ds;
    }

    public static CoverageStoreInfo createCoverageStore(String name, WorkspaceInfo ws) {
        CoverageStoreInfo cs = createNiceMock(CoverageStoreInfo.class);
        expect(cs.getName()).andReturn(name).anyTimes();
        expect(cs.getWorkspace()).andReturn(ws).anyTimes();
        expect(cs.isEnabled()).andReturn(true).anyTimes();
        replay(cs);
        return cs;
    }

    public static FeatureTypeInfo createFeatureType(
            String name, DataStoreInfo ds, NamespaceInfo ns, SimpleFeatureType ft) {
        FeatureTypeInfo ftInfo = createNiceMock(FeatureTypeInfo.class);
        expect(ftInfo.getName()).andReturn(name).anyTimes();
        expect(ftInfo.getStore()).andReturn(ds).anyTimes();
        expect(ftInfo.getNamespace()).andReturn(ns).anyTimes();
        expect(ftInfo.getFeatureType()).andReturn(ft).anyTimes();
        expect(ftInfo.isEnabled()).andReturn(true).anyTimes();
        replay(ftInfo);
        return ftInfo;
    }

    public static CoverageInfo createCoverage(String name, CoverageStoreInfo cs, NamespaceInfo ns) {
        CoverageInfo cInfo = createNiceMock(CoverageInfo.class);
        expect(cInfo.getName()).andReturn(name).anyTimes();
        expect(cInfo.getStore()).andReturn(cs).anyTimes();
        expect(cInfo.getNamespace()).andReturn(ns).anyTimes();
        expect(cInfo.isEnabled()).andReturn(true).anyTimes();
        replay(cInfo);
        return cInfo;
    }

    public static LayerInfo createLayer(ResourceInfo resource) {
        LayerInfo layer = createNiceMock(LayerInfo.class);
        expect(layer.getResource()).andReturn(resource).anyTimes();
        expect(layer.isEnabled()).andReturn(true).anyTimes();
        replay(layer);
        return layer;
    }

    public static StyleInfo createStyle(String name) {
        StyleInfo style = createNiceMock(StyleInfo.class);
        expect(style.getName()).andReturn(name).anyTimes();
        replay(style);
        return style;
    }

    public static LayerGroupInfo createLayerGroup(String name, List<PublishedInfo> layers) {
        LayerGroupInfo lg = createNiceMock(LayerGroupInfo.class);
        expect(lg.getName()).andReturn(name).anyTimes();
        expect(lg.getLayers()).andReturn(layers).anyTimes();
        replay(lg);
        return lg;
    }

    public static GeoServerPBEPasswordEncoder createPasswordEncoder() {
        GeoServerPBEPasswordEncoder encoder = mock(GeoServerPBEPasswordEncoder.class);
        when(encoder.encodePassword(anyObject(String.class), anyObject())).thenReturn("mockedPassword");
        return encoder;
    }

    public static Authentication createAuthentication(String username, String... roles) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String role : roles) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        return new TestingAuthenticationToken(username, "password", authorities);
    }

    public static void setAuthentication(String username, String... roles) {
        SecurityContextHolder.getContext().setAuthentication(createAuthentication(username, roles));
    }
}
