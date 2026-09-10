/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.web.wicket;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import org.apache.wicket.util.crypt.ICrypt;
import org.apache.wicket.util.tester.WicketTester;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class KeyInSessionAesCryptFactoryTest {

    private WicketTester tester;

    @Before
    public void startApplication() {
        tester = new WicketTester();
    }

    @After
    public void stopApplication() {
        tester.destroy();
    }

    @Test
    public void testCryptRoundTripsWithinASession() {
        ICrypt crypt = new KeyInSessionAesCryptFactory().newCrypt();
        assertNotNull(crypt);
        String url = "wicket/bookmarkable/SomePage?1&a=b";
        assertEquals(url, crypt.decryptUrlSafe(crypt.encryptUrlSafe(url)));
        // same session, same key: Wicket's URL comparison depends on this
        assertEquals(
                crypt.encryptUrlSafe(url),
                new KeyInSessionAesCryptFactory().newCrypt().encryptUrlSafe(url));
    }

    @Test
    public void testEachSessionGetsItsOwnKey() {
        String url = "wicket/bookmarkable/SomePage?1&a=b";
        String first = new KeyInSessionAesCryptFactory().newCrypt().encryptUrlSafe(url);
        tester.getSession().replaceSession();
        String second = new KeyInSessionAesCryptFactory().newCrypt().encryptUrlSafe(url);
        assertNotEquals(first, second);
    }
}
