package org.geoserver.security;

import java.security.Provider;
import java.security.Security;
import java.util.Set;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TestBCFIPSAlgorithms {
    public static void main(String[] args) {
        // Add BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());

        Provider bc = Security.getProvider("BC");
        if (bc != null) {
            System.out.println("BouncyCastle provider found: " + bc.getName());

            // List all services
            Set<Provider.Service> services = bc.getServices();
            for (Provider.Service service : services) {
                if (service.getType().equals("Cipher") && service.getAlgorithm().contains("PBE")) {
                    System.out.println("PBE Algorithm: " + service.getAlgorithm());
                }
            }
        } else {
            System.out.println("BouncyCastle provider not found");
        }
    }
}
