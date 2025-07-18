package org.geoserver.security.password;

import java.security.Security;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.SecretKeyFactory;
import org.junit.Test;

public class AlgorithmTest {

    @Test
    public void testAvailableAlgorithms() {
        System.out.println("Available SecretKeyFactory algorithms:");
        Set<String> algorithms = new TreeSet<>();

        // Get algorithms from all providers
        for (java.security.Provider provider : Security.getProviders()) {
            for (java.security.Provider.Service service : provider.getServices()) {
                if ("SecretKeyFactory".equals(service.getType())) {
                    algorithms.add(service.getAlgorithm());
                }
            }
        }

        for (String algorithm : algorithms) {
            System.out.println("  " + algorithm);
        }

        // Test specific algorithms
        String[] testAlgorithms = {
            "PBEWITHSHA256AND128BITAES-CBC",
            "PBEWITHSHA256AND128BITAES-CBC-BC",
            "PBEWITHSHA256AND256BITAES-CBC",
            "PBEWITHSHA256AND256BITAES-CBC-BC",
            "PBEWITHSHA1ANDDESEDE",
            "PBEWITHSHA1ANDDESEDE-BC",
            "PBEWITHSHA1AND128BITAES-CBC-BC",
            "PBEWITHSHA1AND192BITAES-CBC-BC",
            "PBEWITHSHA1AND256BITAES-CBC-BC"
        };

        System.out.println("\nTesting specific algorithms:");
        for (String algorithm : testAlgorithms) {
            try {
                SecretKeyFactory.getInstance(algorithm);
                System.out.println("  " + algorithm + " - AVAILABLE");
            } catch (Exception e) {
                System.out.println("  " + algorithm + " - NOT AVAILABLE: " + e.getMessage());
            }
        }
    }
}
