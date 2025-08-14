/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.SortedSet;
import org.geoserver.security.GeoServerRoleService;
import org.geoserver.security.impl.GeoServerRole;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

public class LDAPRoleServiceTest extends LDAPBaseTest {

    GeoServerRoleService service;

    public void createRoleService(boolean userFilter, Boolean convertToUpperCase, String rolePrefix)
            throws IOException {
        service = new LDAPRoleService();
        if (userFilter) {
            config.setGroupSearchFilter("member={1},dc=example,dc=com");
            config.setUserFilter("uid={0}");
        } else {
            config.setGroupSearchFilter("member=cn={0}");
        }
        if (convertToUpperCase != null) {
            config.setConvertToUpperCase(convertToUpperCase);
        }
        if (rolePrefix != null) {
            config.setRolePrefix(rolePrefix);
        }
        service.initializeFromConfig(config);
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    protected void configureAuthentication() {
        config.setUser("uid=admin,ou=People,dc=example,dc=com"); // ("uid=admin,ou=People,dc=example,dc=com");
        config.setPassword("admin");
        config.setBindBeforeGroupSearch(true);
    }

    protected void checkAdminRoles() throws IOException {
        config.setAdminGroup("admin");
        config.setGroupAdminGroup("other");
        createRoleService(false, null, null);

        assertNotNull(service.getAdminRole());
        assertNotNull(service.getGroupAdminRole());

        config.setAdminGroup("dummy1");
        config.setGroupAdminGroup("dummy2");
        createRoleService(false, null, null);

        assertNull(service.getAdminRole());
        assertNull(service.getGroupAdminRole());

        config.setAdminGroup("admin");
        config.setGroupAdminGroup("other");
        createRoleService(false, false, "test_");
        assertEquals("test_admin", service.getAdminRole().toString());
    }

    protected void checkUserNamesForRole(String roleName, int expected, boolean userFilter) throws IOException {
        createRoleService(userFilter, null, null);

        SortedSet<String> userNames = service.getUserNamesForRole(new GeoServerRole(roleName));
        assertNotNull(userNames);
        assertEquals(expected, userNames.size());

        createRoleService(userFilter, false, "test_");

        userNames = service.getUserNamesForRole(new GeoServerRole(roleName));
        assertNotNull(userNames);
        assertEquals(expected, userNames.size());
    }

    protected void checkRoleByName() throws IOException {
        createRoleService(false, null, null);

        assertNotNull(service.getRoleByName("admin"));
        assertNull(service.getRoleByName("dummy"));

        createRoleService(false, false, "test_");

        assertNotNull(service.getRoleByName("admin"));
        assertNull(service.getRoleByName("dummy"));
    }

    protected void checkRoleCount() throws IOException {
        createRoleService(false, null, null);

        assertTrue(service.getRoleCount() > 0);

        createRoleService(false, false, "test_");

        assertTrue(service.getRoleCount() > 0);
    }

    protected void checkAllRoles() throws IOException {
        createRoleService(false, null, null);

        SortedSet<GeoServerRole> roles = service.getRoles();
        assertNotNull(roles);
        assertFalse(roles.isEmpty());
        GeoServerRole role = roles.first();
        assertTrue(role.toString().startsWith("ROLE_"));
        assertEquals(role.toString().toUpperCase(), role.toString());

        createRoleService(false, false, "test_");

        roles = service.getRoles();
        assertNotNull(roles);
        assertFalse(roles.isEmpty());
        role = roles.first();
        assertTrue(role.toString().startsWith("test_"));
        assertNotEquals(role.toString().toUpperCase(), role.toString());
    }

    protected void checkUserRoles(String username, boolean userFilter) throws IOException {
        createRoleService(userFilter, null, null);
        SortedSet<GeoServerRole> allRoles = service.getRoles();
        SortedSet<GeoServerRole> roles = service.getRolesForUser(username);
        assertNotNull(roles);
        assertFalse(roles.isEmpty());
        assertTrue(roles.size() < allRoles.size());
        GeoServerRole role = roles.first();
        assertTrue(role.toString().startsWith("ROLE_"));
        assertEquals(role.toString().toUpperCase(), role.toString());

        createRoleService(userFilter, false, "test_");
        allRoles = service.getRoles();
        roles = service.getRolesForUser(username);
        assertNotNull(roles);
        assertFalse(roles.isEmpty());
        assertTrue(roles.size() < allRoles.size());
        role = roles.first();
        assertTrue(role.toString().startsWith("test_"));
        assertNotEquals(role.toString().toUpperCase(), role.toString());
    }

    @Override
    protected void createConfig() {
        config = new LDAPRoleServiceConfig();
    }

    public static class LDAPRoleServiceLdiffTest extends LDAPRoleServiceTest {

        @BeforeClass
        public static void setUpLdapServerLdiff() throws Exception {
            UnboundIDLDAPTestServer.reloadData(new ClassPathResource("data.ldif"));
        }

        @AfterClass
        public static void tearDownLdapServerLdiff() throws Exception {
            UnboundIDLDAPTestServer.reloadData(new ClassPathResource("data.ldif"));
        }

        @Test
        public void testGetRoles() throws Exception {
            checkAllRoles();
        }

        @Test
        public void testGetRolesAuthenticated() throws Exception {
            configureAuthentication();
            checkAllRoles();
        }

        @Test
        public void testGetRolesCount() throws Exception {
            checkRoleCount();
        }

        @Test
        public void testGetRolesCountAuthenticated() throws Exception {
            configureAuthentication();
            checkRoleCount();
        }

        @Test
        public void testGetRoleByName() throws Exception {
            checkRoleByName();
        }

        @Test
        public void testGetRoleByNameAuthenticated() throws Exception {
            configureAuthentication();
            checkRoleByName();
        }

        @Test
        public void testGetAdminRoles() throws Exception {
            checkAdminRoles();
        }

        @Test
        public void testGetAdminRolesAuthenticated() throws Exception {
            configureAuthentication();
            checkAdminRoles();
        }

        @Test
        public void testGetRolesForUser() throws Exception {
            checkUserRoles("admin", false);
        }

        @Test
        public void testGetRolesForUserAuthenticated() throws Exception {
            configureAuthentication();
            checkUserRoles("admin", false);
        }

        @Test
        public void testGetUserNamesForRole() throws Exception {
            checkUserNamesForRole("admin", 1, false);
            checkUserNamesForRole("other", 2, false);
        }

        /** Tests LDAP Hierarchical roles retrieval for an user. */
        @Test
        public void checkUserHierarchicalRoles() throws IOException {
            config.setUseNestedParentGroups(true);
            config.setNestedGroupSearchFilter("member=cn={0}");
            config.setGroupSearchFilter("member=cn={0}");
            config.setUserFilter("uid={0}");
            service = new LDAPRoleService();
            service.initializeFromConfig(config);
            SortedSet<GeoServerRole> roles = service.getRolesForUser("nestedUser");
            assertNotNull(roles);
            assertEquals(2, roles.size());
            // check parent role ROLE_EXTRA
            assertTrue(roles.stream().anyMatch(r -> "ROLE_EXTRA".equals(r.getAuthority())));
        }
    }

    public static class LDAPRoleServiceLdiff2Test extends LDAPRoleServiceTest {

        @BeforeClass
        public static void setUpLdapServerLdiff2() throws Exception {
            UnboundIDLDAPTestServer.reloadData(new ClassPathResource("data2.ldif"));
        }

        @AfterClass
        public static void tearDownLdapServerLdiff2() throws Exception {
            UnboundIDLDAPTestServer.reloadData(new ClassPathResource("data.ldif"));
        }

        @Test
        public void testGetRolesForUserUsingUserFilter() throws Exception {
            checkUserRoles("admin", true);
        }

        @Test
        public void testGetRolesForUserAuthenticatedUsingUserFilter() throws Exception {
            configureAuthentication();
            checkUserRoles("admin", true);
        }

        @Test
        public void testGetUserNamesForRoleUsingUserFilter() throws Exception {
            checkUserNamesForRole("admin", 1, true);
            checkUserNamesForRole("other", 2, true);
        }
    }

    public static class LDAPRoleServiceLdiff4Test extends LDAPRoleServiceTest {

        @BeforeClass
        public static void setUpLdapServerLdiff4() throws Exception {
            UnboundIDLDAPTestServer.reloadData(new ClassPathResource("data4.ldif"));
        }

        @AfterClass
        public static void tearDownLdapServerLdiff4() throws Exception {
            UnboundIDLDAPTestServer.reloadData(new ClassPathResource("data.ldif"));
        }

        @Test
        public void checkHierarchicalRolesUsers() throws IOException {
            createRoleService(true, null, null);
            config.setUserNameAttribute("uid");
            config.setGroupNameAttribute("cn");
            config.setUseNestedParentGroups(true);
            // ,dc=example,dc=com
            config.setNestedGroupSearchFilter("member={1}");
            config.setGroupSearchFilter("member={1},dc=example,dc=com");
            config.setUserFilter("uid={0}");
            config.setMaxGroupSearchLevel(5);
            service = new LDAPRoleService();
            service.initializeFromConfig(config);
            SortedSet<String> userNames = service.getUserNamesForRole(service.getRoleByName("ROLE_EXTRA"));
            assertNotNull(userNames);
            assertEquals(2, userNames.size());
            // check parent role ROLE_EXTRA
            assertTrue(userNames.stream().anyMatch(u -> "nestedUser".equals(u)));
            // check nested roles
            SortedSet<GeoServerRole> roles = service.getRolesForUser("nestedUser");
            assertEquals(6, roles.size());
        }
    }
}
