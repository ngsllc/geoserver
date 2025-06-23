/*
 * Copyright (c) 2024 Open Source Geospatial Foundation (OSGeo)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.geoserver.security;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MigrateKeystore {
    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println(
                    "Usage: MigrateKeystore <old_keystore> <old_password> <new_keystore> <new_password> [new_keystore_type] [new_provider] [old_keystore_type] [old_provider]");
            System.out.println("  new_keystore_type: JCEKS (default), BCFKS, or other JVM-supported types");
            System.out.println("  new_provider: BCFIPS (for BCFKS) or other provider name");
            System.out.println("  old_keystore_type: JCEKS (default), BCFKS, or other JVM-supported types");
            System.out.println("  old_provider: BCFIPS (for BCFKS) or other provider name");
            System.exit(1);
        }

        String oldKeystorePath = args[0];
        String oldPassword = args[1];
        String newKeystorePath = args[2];
        String newPassword = args[3];
        String newKeystoreType = args.length > 4 ? args[4] : KeyStoreProviderImpl.getKeyStoreType();
        String newProvider = args.length > 5 ? args[5] : KeyStoreProviderImpl.getKeyStoreProvider();
        String oldKeystoreType = args.length > 6 ? args[6] : "JCEKS";
        String oldProvider = args.length > 7 ? args[7] : null;

        // Initialize Bouncy Castle provider if needed for new keystore
        if (KeyStoreProviderImpl.BCFKS_KEYSTORE_TYPE.equals(newKeystoreType) && Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        // Initialize Bouncy Castle provider if needed for old keystore
        if (KeyStoreProviderImpl.BCFKS_KEYSTORE_TYPE.equals(oldKeystoreType) && Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Load old keystore
        KeyStore oldKeystore;
        if (oldProvider != null && !oldProvider.isEmpty()) {
            oldKeystore = KeyStore.getInstance(oldKeystoreType, oldProvider);
        } else {
            oldKeystore = KeyStore.getInstance(oldKeystoreType);
        }
        try (FileInputStream fis = new FileInputStream(oldKeystorePath)) {
            oldKeystore.load(fis, oldPassword.toCharArray());
        }

        // Create new keystore
        KeyStore newKeystore;
        if (newProvider != null && !newProvider.isEmpty()) {
            newKeystore = KeyStore.getInstance(newKeystoreType, newProvider);
        } else {
            newKeystore = KeyStore.getInstance(newKeystoreType);
        }
        newKeystore.load(null, newPassword.toCharArray());

        // Migrate entries
        Enumeration<String> aliases = oldKeystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (oldKeystore.isKeyEntry(alias)) {
                Key key = oldKeystore.getKey(alias, oldPassword.toCharArray());
                Certificate[] certChain = oldKeystore.getCertificateChain(alias);
                KeyStore.Entry entry;
                if (key instanceof SecretKey) {
                    entry = new KeyStore.SecretKeyEntry((SecretKey) key);
                } else if (key instanceof PrivateKey && certChain != null) {
                    entry = new KeyStore.PrivateKeyEntry((PrivateKey) key, certChain);
                } else {
                    System.out.println("Skipping unknown key type for alias: " + alias);
                    continue;
                }
                newKeystore.setEntry(alias, entry, new KeyStore.PasswordProtection(newPassword.toCharArray()));
            } else if (oldKeystore.isCertificateEntry(alias)) {
                Certificate cert = oldKeystore.getCertificate(alias);
                newKeystore.setCertificateEntry(alias, cert);
            }
        }

        // Save new keystore
        try (FileOutputStream fos = new FileOutputStream(newKeystorePath)) {
            newKeystore.store(fos, newPassword.toCharArray());
        }

        System.out.println("Migration completed successfully.");
        System.out.println("Old keystore: " + oldKeystorePath + " (" + oldKeystoreType
                + (oldProvider != null && !oldProvider.isEmpty() ? "/" + oldProvider : "") + ")");
        System.out.println("New keystore: " + newKeystorePath + " (" + newKeystoreType
                + (newProvider != null && !newProvider.isEmpty() ? "/" + newProvider : "") + ")");
    }
}
