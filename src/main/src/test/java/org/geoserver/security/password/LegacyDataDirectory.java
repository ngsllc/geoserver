/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.geoserver.security.password.LegacyPasswordFixtures.ADMIN_CRYPT2;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.crypto.spec.SecretKeySpec;
import org.geoserver.data.test.SystemTestData;

/**
 * Stages the security directory of a GeoServer 2.x, or pieces of it, for tests of what happens to such a directory on
 * the first start of a newer one: the canned {@code security.zip}, with its passwords rewritten the way the password
 * based encoders stored them.
 */
public final class LegacyDataDirectory {

    /** Master password of the canned security directory. */
    public static final char[] MASTER_PASSWORD = "geoserver".toCharArray();

    private LegacyDataDirectory() {}

    /** Unpacks the canned security directory, skipping the named entries, into an existing security directory. */
    public static void unpackCanned(File security, Set<String> skip) throws IOException {
        try (ZipInputStream zip = new ZipInputStream(SystemTestData.class.getResourceAsStream("security.zip"))) {
            for (ZipEntry entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                File target = new File(security, entry.getName());
                if (entry.isDirectory()) {
                    target.mkdirs();
                    continue;
                }
                if (skip.contains(entry.getName())) {
                    continue;
                }
                target.getParentFile().mkdirs();
                try (OutputStream out = new FileOutputStream(target)) {
                    zip.transferTo(out);
                }
            }
        }
    }

    /**
     * Adds a secret to a keystore, creating the file when there is none. The label is the one GeoServer stores its
     * secrets under; a keystore written by GeoServer 2.x labels them {@code PBE}, which BCFKS refuses, and the tests of
     * the move from JCEKS use the canned file for that.
     */
    public static void setSecretKey(File keystore, String type, String alias, String secret)
            throws IOException, GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance(type);
        if (keystore.exists()) {
            try (InputStream in = new FileInputStream(keystore)) {
                ks.load(in, MASTER_PASSWORD);
            }
        } else {
            ks.load(null, MASTER_PASSWORD);
        }
        ks.setEntry(
                alias,
                new KeyStore.SecretKeyEntry(
                        new SecretKeySpec(secret.getBytes(StandardCharsets.US_ASCII), "HmacSHA256")),
                new KeyStore.PasswordProtection(MASTER_PASSWORD));
        try (OutputStream out = new FileOutputStream(keystore)) {
            ks.store(out, MASTER_PASSWORD);
        }
    }

    /**
     * Switches the default user group service to the {@code crypt2} encoder, with the admin password stored as
     * {@link LegacyPasswordFixtures#ADMIN_CRYPT2}, under {@link LegacyPasswordFixtures#USER_GROUP_KEY}.
     */
    public static void stageCrypt2UserPasswords(File security) throws IOException {
        replace(
                new File(security, "usergroup/default/users.xml"),
                "password=\"digest1:[^\"]*\"",
                "password=\"" + ADMIN_CRYPT2 + "\"");
        replace(
                new File(security, "usergroup/default/config.xml"),
                "<passwordEncoderName>digestPasswordEncoder</passwordEncoderName>",
                "<passwordEncoderName>strongPbePasswordEncoder</passwordEncoderName>");
    }

    /**
     * Adds a user row to the default user group service with the stored password given verbatim, so a test can stage a
     * value the migration will not be able to read, or one written under a known key.
     */
    public static void addUser(File security, String username, String storedPassword) throws IOException {
        File users = new File(security, "usergroup/default/users.xml");
        String xml = Files.readString(users.toPath(), StandardCharsets.UTF_8);
        String row = "        <user enabled=\"true\" name=\"" + username + "\" password=\"" + storedPassword + "\"/>\n";
        String changed = xml.replace("    </users>", row + "    </users>");
        if (changed.equals(xml)) {
            throw new IllegalStateException(users + " has no </users> to add a user before");
        }
        Files.writeString(users.toPath(), changed, StandardCharsets.UTF_8);
    }

    /** Names the configuration password encoder in the security configuration. */
    public static void setConfigPasswordEncoder(File security, String encoderName) throws IOException {
        replace(
                new File(security, "config.xml"),
                "<configPasswordEncrypterName>[^<]*</configPasswordEncrypterName>",
                "<configPasswordEncrypterName>" + encoderName + "</configPasswordEncrypterName>");
    }

    /**
     * Stores the master password the way {@link AesGcmMasterPasswordProvider} does, with the configuration naming that
     * provider, in place of the canned MD5/DES file that a FIPS provider cannot read.
     */
    public static void stageAesGcmMasterPassword(File security) throws IOException {
        File dir = new File(security, "masterpw/default");
        dir.mkdirs();
        Files.writeString(
                new File(dir, "config.xml").toPath(),
                """
                <aesGcmUrlProvider>
                  <id>52857278:13c7ffd66a8:-8000</id>
                  <name>default</name>
                  <className>org.geoserver.security.password.AesGcmMasterPasswordProvider</className>
                  <readOnly>false</readOnly>
                  <url>file:passwd</url>
                  <encrypting>true</encrypting>
                </aesGcmUrlProvider>
                """,
                StandardCharsets.UTF_8);
        Files.write(new File(dir, "passwd").toPath(), new AesGcmMasterPasswordProvider().encrypt(MASTER_PASSWORD));
    }

    private static void replace(File file, String regex, String replacement) throws IOException {
        String text = Files.readString(file.toPath(), StandardCharsets.UTF_8);
        String changed = text.replaceFirst(regex, replacement);
        if (changed.equals(text)) {
            throw new IllegalStateException(file + " holds nothing matching " + regex);
        }
        Files.writeString(file.toPath(), changed, StandardCharsets.UTF_8);
    }
}
