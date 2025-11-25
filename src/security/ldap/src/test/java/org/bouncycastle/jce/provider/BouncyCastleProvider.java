package org.bouncycastle.jce.provider;

import java.security.Provider;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

public class BouncyCastleProvider extends Provider {
    public BouncyCastleProvider() {
        super("BC", 1.56, "BouncyCastle Security Provider v1.56 (Simulated for FIPS)");

        Provider fipsProvider = new BouncyCastleFipsProvider();
        // Copy all services/properties from FIPS provider to this one
        for (Object key : fipsProvider.keySet()) {
            Object value = fipsProvider.get(key);
            this.put(key, value);
        }
    }
}
