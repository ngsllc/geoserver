/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.geoserver.security.FipsRuntime;
import org.geoserver.security.KeyStoreProviderImpl;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Runs GeoServer's FIPS cryptography on a thread in BouncyCastle's approved-only mode, with the FIPS provider first,
 * the way a FIPS deployment runs it. Approved-only mode is set on a throwaway thread, so the rest of the JVM is left as
 * it was: the mode cannot be undone once set, and it is not inherited by other threads.
 */
public class FipsApprovedOnlyTest {

    private String originalFipsMode;

    @Before
    public void fipsModeOn() {
        originalFipsMode = System.getProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, "true");
        assertTrue("bc-fips must be on the test classpath", FipsRuntime.registerProvider());
    }

    @After
    public void fipsModeOff() {
        if (originalFipsMode == null) {
            System.clearProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR);
        } else {
            System.setProperty(KeyStoreProviderImpl.FIPS_MODE_ENV_VAR, originalFipsMode);
        }
        // back to where a non-FIPS test JVM has it: appended, behind the JDK providers
        Security.removeProvider(KeyStoreProviderImpl.BCFIPS_PROVIDER);
        FipsRuntime.registerProvider();
    }

    @Test
    public void testProviderIsFirstInFipsMode() {
        assertEquals(KeyStoreProviderImpl.BCFIPS_PROVIDER, Security.getProviders()[0].getName());
        assertEquals("first", FipsRuntime.describeProviderPosition());
    }

    @Test
    public void testEverythingGeoServerWritesIsApproved() throws Throwable {
        runApprovedOnly(() -> {
            assertTrue(FipsRuntime.isApprovedOnlyForThisThread());

            // the random source is the validated module's DRBG
            assertEquals(
                    KeyStoreProviderImpl.BCFIPS_PROVIDER,
                    FipsRuntime.secureRandom().getProvider().getName());

            // crypt3: key derivation, encryption, decryption, upstream value
            SecretKey key = AesGcmCipher.deriveKey(AesGcmCipherTest.UPSTREAM_SECRET.toCharArray());
            assertEquals(
                    AesGcmCipherTest.UPSTREAM_DERIVED_KEY, Base64.getEncoder().encodeToString(key.getEncoded()));
            byte[] plain = "approved".getBytes(StandardCharsets.UTF_8);
            assertArrayEquals(plain, AesGcmCipher.decrypt(key, AesGcmCipher.encrypt(key, plain)));
            assertEquals(
                    AesGcmCipherTest.UPSTREAM_PLAINTEXT,
                    new String(
                            AesGcmCipher.decrypt(key, Base64.getDecoder().decode(AesGcmCipherTest.UPSTREAM_CIPHERTEXT)),
                            StandardCharsets.UTF_8));

            // values written by earlier builds stay readable, without asking the provider for their cipher
            assertEquals(
                    Pkcs12PbeTest.PLAINTEXT,
                    new String(
                            Pkcs12Pbe.decrypt(
                                    Pkcs12PbeTest.PASSWORD,
                                    Base64.getDecoder().decode(Pkcs12PbeTest.WITH_IV),
                                    256,
                                    true),
                            StandardCharsets.UTF_8));

            // the keystore, holding a secret stored the way GeoServer stores them
            KeyStore ks = KeyStore.getInstance(
                    KeyStoreProviderImpl.BCFKS_KEYSTORE_TYPE, KeyStoreProviderImpl.BCFIPS_PROVIDER);
            ks.load(null, null);
            char[] pw = "keystore".toCharArray();
            ks.setEntry(
                    "k",
                    new KeyStore.SecretKeyEntry(
                            new SecretKeySpec(new byte[40], KeyStoreProviderImpl.LEGACY_SECRET_KEY_ALGORITHM)),
                    new KeyStore.PasswordProtection(pw));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ks.store(out, pw);
            KeyStore reloaded = KeyStore.getInstance(
                    KeyStoreProviderImpl.BCFKS_KEYSTORE_TYPE, KeyStoreProviderImpl.BCFIPS_PROVIDER);
            reloaded.load(new ByteArrayInputStream(out.toByteArray()), pw);
            assertEquals(40, reloaded.getKey("k", pw).getEncoded().length);
            return null;
        });
    }

    @Test
    public void testTheEarlierCipherIsGone() throws Throwable {
        runApprovedOnly(() -> {
            // this is what the crypt2 encoder, master password file and URL keys were built on; in approved-only
            // mode the provider does not offer it, which is why Pkcs12Pbe exists
            assertThrows(
                    NoSuchAlgorithmException.class,
                    () -> Cipher.getInstance(
                            KeyStoreProviderImpl.FIPS_PBE_ALGORITHM, KeyStoreProviderImpl.BCFIPS_PROVIDER));
            return null;
        });
    }

    private static void runApprovedOnly(java.util.concurrent.Callable<Void> body) throws Throwable {
        Throwable[] failure = new Throwable[1];
        Thread thread = new Thread(() -> {
            try {
                CryptoServicesRegistrar.setApprovedOnlyMode(true);
                body.call();
            } catch (Throwable t) {
                failure[0] = t;
            }
        });
        thread.start();
        thread.join();
        if (failure[0] != null) {
            throw failure[0];
        }
    }
}
