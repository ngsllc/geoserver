/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

/**
 * Passwords as a GeoServer 2.x with the regular BouncyCastle provider stores them, made with jasypt 1.9.3 and the
 * defaults of the two password based encoders. They stand for what a data directory holds before it is moved to the
 * FIPS provider, and have to stay readable after.
 */
public final class LegacyPasswordFixtures {

    private LegacyPasswordFixtures() {}

    /**
     * Under the configuration key of the canned test keystore ({@code security.zip}, alias {@code config:password:key},
     * master password {@code geoserver}). Regenerate along with the keystore if that ever changes.
     */
    public static final String CANNED_PLAINTEXT = "upstream-store-secret";

    /** {@code strongPbePasswordEncoder}: PBEWITHSHA256AND256BITAES-CBC-BC on provider BC */
    public static final String CANNED_CRYPT2 =
            "crypt2:WTm4g92u0dkA3K5rubBmP8v8vG+4ZaPDlifgIYCLG4V85Be7ru4vPM45h6jQ58Is";

    /** {@code pbePasswordEncoder}: PBEWithMD5AndDES */
    public static final String CANNED_CRYPT1 = "crypt1:PNMxJc2IAr99o6R5fQGabbs0jymPAxmnINmURi865EA=";

    /** A configuration key a test stages itself, and the values written under it. */
    public static final String CONFIG_KEY = "config-key-for-fips-tests-0123456789abcdef";

    public static final String CONFIG_PLAINTEXT = "store-secret";

    public static final String CONFIG_CRYPT2 = "crypt2:clTbdhAe/gHF0kC4BIBQNCqFsi5zjWrTSFVhxR/bv0M=";

    public static final String CONFIG_CRYPT1 = "crypt1:an31vroYgMDDZp8Z2760P+LUp9Y9xlYm";

    /** A user group service key a test stages itself, and the admin password written under it. */
    public static final String USER_GROUP_KEY = "usergroup-key-for-fips-tests-0123456789ab";

    public static final String ADMIN_PASSWORD = "geoserver";

    public static final String ADMIN_CRYPT2 = "crypt2:Xy22jv6ushfgyFFQpEaumKpbsw0zz4e9ia9EQRP4V/Y=";

    public static final String ADMIN_CRYPT1 = "crypt1:EAx6I/w61HEZ9uHnhEdKISg4myftJIOd";
}
