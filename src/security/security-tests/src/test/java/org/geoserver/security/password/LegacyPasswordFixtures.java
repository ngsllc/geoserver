/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

/**
 * Passwords encrypted by upstream GeoServer 2.28 (stock BouncyCastle, Jasypt defaults) with the configuration key of
 * the system test keystore ({@code security.zip}, alias {@code config:password:key}, a 40 character "PBE" key). They
 * are what a data directory created before FIPS support contains, and must stay readable after the upgrade. If the test
 * keystore is ever regenerated these fixtures have to be regenerated with it.
 */
final class LegacyPasswordFixtures {

    static final String PLAINTEXT = "upstream-store-secret";

    /** {@code strongPbePasswordEncoder}: PBEWITHSHA256AND256BITAES-CBC-BC on provider BC, no explicit IV */
    static final String CRYPT2 = "crypt2:WTm4g92u0dkA3K5rubBmP8v8vG+4ZaPDlifgIYCLG4V85Be7ru4vPM45h6jQ58Is";

    /** {@code pbePasswordEncoder}: PBEWithMD5AndDES, Jasypt defaults */
    static final String CRYPT1 = "crypt1:PNMxJc2IAr99o6R5fQGabbs0jymPAxmnINmURi865EA=";

    private LegacyPasswordFixtures() {}
}
