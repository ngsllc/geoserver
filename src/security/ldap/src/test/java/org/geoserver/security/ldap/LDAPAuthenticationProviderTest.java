/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.MemoryRoleService;
import org.geoserver.security.impl.MemoryRoleStore;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/** @author "Mauro Bartolomeoli - mauro.bartolomeoli@geo-solutions.it" */
public class LDAPAuthenticationProviderTest extends LDAPBaseTest {

    protected LDAPAuthenticationProvider authProvider;

    @Override
    protected void createConfig() {
        config = new LDAPSecurityServiceConfig();
    }

    protected void createAuthenticationProvider() {
        authProvider = (LDAPAuthenticationProvider) securityProvider.createAuthenticationProvider(config);
    }

    public static class LDAPAuthenticationProviderDataTest extends LDAPAuthenticationProviderTest {

        /**
         * Test that bindBeforeGroupSearch correctly enables roles fetching. Note: UnboundID In-Memory LDAP server
         * allows anonymous access by default.
         */
        @Test
        public void testBindBeforeGroupSearch() throws Exception {
            // UnboundID allows anonymous access by default

            ((LDAPSecurityServiceConfig) config).setUserDnPattern("uid={0},ou=People");
            config.setBindBeforeGroupSearch(true);
            createAuthenticationProvider();

            Authentication result = authProvider.authenticate(authentication);
            assertNotNull(result);
            assertEquals("admin", result.getName());
            assertEquals(3, result.getAuthorities().size());
        }

        /**
         * Test that group search works without bindBeforeGroupSearch when anonymous access is
         * allowed. UnboundID In-Memory LDAP server allows anonymous access by default, so this
         * verifies the no-bind path succeeds.
         */
        @Test
        public void testGroupSearchWorksWithoutBindWhenAnonymousAllowed() throws Exception {
            // UnboundID In-Memory LDAP allows anonymous access by default
            ((LDAPSecurityServiceConfig) config).setUserDnPattern("uid={0},ou=People");
            // we don't bind
            config.setBindBeforeGroupSearch(false);
            createAuthenticationProvider();

            // This should work with UnboundID since anonymous is allowed
            Authentication result = authProvider.authenticate(authentication);
            assertNotNull(result);
            assertEquals(3, result.getAuthorities().size());
        }

        /** Test that authentication can be done using the couple userFilter and userFormat instead of userDnPattern. */
        @Test
        public void testUserFilterAndFormat() throws Exception {
            // filter to extract user data
            config.setUserFilter("(telephonenumber=1)");
            // username to bind to
            ((LDAPSecurityServiceConfig) config).setUserFormat("uid={0},ou=People,dc=example,dc=com");

            createAuthenticationProvider();

            Authentication result = authProvider.authenticate(authentication);
            assertEquals(3, result.getAuthorities().size());
        }

        /**
         * Test that authentication can be done using the couple userFilter and userFormat instead of userDnPattern,
         * using placemarks in userFilter.
         */
        @Test
        public void testUserFilterPlacemarks() throws Exception {
            // filter to extract user data
            config.setUserFilter("(givenName={1})");
            // username to bind to
            ((LDAPSecurityServiceConfig) config).setUserFormat("uid={0},ou=People,dc=example,dc=com");

            createAuthenticationProvider();

            Authentication result = authProvider.authenticate(authentication);
            assertEquals(3, result.getAuthorities().size());

            // filter to extract user data
            config.setUserFilter("(cn={0})");
            // username to bind to
            ((LDAPSecurityServiceConfig) config).setUserFormat("uid={0},ou=People,dc=example,dc=com");

            createAuthenticationProvider();

            result = authProvider.authenticate(authentication);
            assertEquals(3, result.getAuthorities().size());
        }

        /** Test that if and adminGroup is defined, the roles contain ROLE_ADMINISTRATOR */
        @Test
        public void testAdminGroup() throws Exception {
            ((LDAPSecurityServiceConfig) config).setUserDnPattern("uid={0},ou=People");
            config.setAdminGroup("other");

            createAuthenticationProvider();

            Authentication result = authProvider.authenticate(authenticationOther);
            boolean foundAdmin = false;
            for (GrantedAuthority authority : result.getAuthorities()) {
                if (authority.getAuthority().equalsIgnoreCase("ROLE_ADMINISTRATOR")) {
                    foundAdmin = true;
                }
            }
            assertTrue(foundAdmin);
        }

        /** Test that if and groupAdminGroup is defined, the roles contain ROLE_GROUP_ADMIN */
        @Test
        public void testGroupAdminGroup() throws Exception {
            ((LDAPSecurityServiceConfig) config).setUserDnPattern("uid={0},ou=People");
            config.setGroupAdminGroup("other");

            createAuthenticationProvider();

            Authentication result = authProvider.authenticate(authenticationOther);
            boolean foundAdmin = false;
            for (GrantedAuthority authority : result.getAuthorities()) {
                if (authority.getAuthority().equalsIgnoreCase("ROLE_GROUP_ADMIN")) {
                    foundAdmin = true;
                }
            }
            assertTrue(foundAdmin);
        }

        /** Test that active role service is applied in the LDAPAuthenticationProvider */
        @Test
        public void testRoleService() throws Exception {
            ((LDAPSecurityServiceConfig) config).setUserDnPattern("uid={0},ou=People");

            createAuthenticationProvider();

            authProvider.setSecurityManager(securityManager);
            securityManager.setProviders(Collections.singletonList(authProvider));
            MemoryRoleStore roleService = new MemoryRoleStore();
            roleService.initializeFromService(new MemoryRoleService());
            roleService.setSecurityManager(securityManager);
            GeoServerRole role = roleService.createRoleObject("MyRole");
            roleService.addRole(role);
            roleService.associateRoleToUser(role, "other");
            securityManager.setActiveRoleService(roleService);

            Authentication result = authProvider.authenticate(authenticationOther);
            assertTrue(result.getAuthorities().contains(role));
            assertEquals(3, result.getAuthorities().size());
        }

        /** Tests LDAP hierarchical nested groups search. */
        @Test
        public void testHierarchicalGroupSearch() throws Exception {

            ((LDAPSecurityServiceConfig) config).setUserDnPattern("uid={0},ou=People");
            config.setBindBeforeGroupSearch(false);
            // activate hierarchical group search
            config.setUseNestedParentGroups(true);
            config.setNestedGroupSearchFilter("member=cn={1}");
            createAuthenticationProvider();

            Authentication result = authProvider.authenticate(authenticationNested);
            assertNotNull(result);
            assertEquals("nestedUser", result.getName());
            assertEquals(3, result.getAuthorities().size());
            assertTrue(result.getAuthorities().stream().anyMatch(x -> "ROLE_NESTED".equals(x.getAuthority())));
            assertTrue(result.getAuthorities().stream().anyMatch(x -> "ROLE_EXTRA".equals(x.getAuthority())));
        }

        /** Tests LDAP hierarchical nested groups search. */
        @Test
        public void testBindBeforeHierarchicalGroupSearch() throws Exception {

            ((LDAPSecurityServiceConfig) config).setUserDnPattern("uid={0},ou=People");
            config.setBindBeforeGroupSearch(true);
            // activate hierarchical group search
            config.setUseNestedParentGroups(true);
            config.setNestedGroupSearchFilter("member=cn={1}");
            createAuthenticationProvider();

            Authentication result = authProvider.authenticate(authenticationNested);
            assertNotNull(result);
            assertEquals("nestedUser", result.getName());
            assertEquals(3, result.getAuthorities().size());
            assertTrue(result.getAuthorities().stream().anyMatch(x -> "ROLE_NESTED".equals(x.getAuthority())));
            assertTrue(result.getAuthorities().stream().anyMatch(x -> "ROLE_EXTRA".equals(x.getAuthority())));
        }

        /** Tests LDAP hierarchical nested groups search disabled. */
        @Test
        public void testBindBeforeHierarchicalDisabledGroupSearch() throws Exception {

            ((LDAPSecurityServiceConfig) config).setUserDnPattern("uid={0},ou=People");
            config.setBindBeforeGroupSearch(true);
            // activate hierarchical group search
            config.setUseNestedParentGroups(false);
            createAuthenticationProvider();

            Authentication result = authProvider.authenticate(authenticationNested);
            assertNotNull(result);
            assertEquals("nestedUser", result.getName());
            assertEquals(2, result.getAuthorities().size());
            assertTrue(result.getAuthorities().stream().anyMatch(x -> "ROLE_NESTED".equals(x.getAuthority())));
            assertTrue(result.getAuthorities().stream().noneMatch(x -> "ROLE_EXTRA".equals(x.getAuthority())));
        }
    }

    public static class LDAPAuthenticationProviderData3Test extends LDAPAuthenticationProviderTest {

        @BeforeClass
        public static void setUpData3() throws Exception {
            // Reload with data3.ldif
            UnboundIDLDAPTestServer.reloadData(new ClassPathResource("data3.ldif"));
        }

        @AfterClass
        public static void tearDownData3() throws Exception {
            // Reload default data
            UnboundIDLDAPTestServer.reloadData(new ClassPathResource("data.ldif"));
        }

        /** Test that LDAPAuthenticationProvider finds roles even if there is a colon in the password */
        @Test
        public void testColonPassword() throws Exception {
            ((LDAPSecurityServiceConfig) config).setUserDnPattern("uid={0},ou=People");

            createAuthenticationProvider();

            authentication = new UsernamePasswordAuthenticationToken("colon", "da:da");

            Authentication result = authProvider.authenticate(authentication);
            assertEquals(2, result.getAuthorities().size());
        }
    }
}
