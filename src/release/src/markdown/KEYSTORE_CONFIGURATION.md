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

# GeoServer Keystore Type Configuration

GeoServer now supports configurable keystore types through environment variables, with JCEKS as the default fallback.

## Environment Variable

Set the `GEOSERVER_KEYSTORE_TYPE` environment variable to specify the keystore type:

```bash
export GEOSERVER_KEYSTORE_TYPE=JCEKS
```

## Supported Keystore Types

### JCEKS (Default)
- **Environment Variable**: `GEOSERVER_KEYSTORE_TYPE=JCEKS`
- **Provider**: Default JVM provider
- **File Extension**: `.jceks`
- **Description**: Java Cryptography Extension KeyStore, the default keystore type for GeoServer

### BCFKS
- **Environment Variable**: `GEOSERVER_KEYSTORE_TYPE=BCFKS`
- **Provider**: BCFIPS (Bouncy Castle FIPS)
- **File Extension**: `.bcfks`
- **Description**: Bouncy Castle FIPS Keystore, provides FIPS-compliant cryptography
- **Requirements**: Bouncy Castle FIPS library must be in the classpath

### Other JVM-Supported Types
Any keystore type supported by the JVM can be used:
- `JKS` - Java KeyStore
- `PKCS12` - PKCS#12 format
- `PKCS11` - PKCS#11 hardware tokens
- And others supported by your JVM

## File Naming

The keystore files are automatically named based on the keystore type:
- Default keystore: `geoserver.{keystore_type}`
- Prepared keystore (for password changes): `geoserver.{keystore_type}.new`

Examples:
- JCEKS: `geoserver.jceks`, `geoserver.jceks.new`
- BCFKS: `geoserver.bcfks`, `geoserver.bcfks.new`
- PKCS12: `geoserver.p12`, `geoserver.p12.new`

## Migration

The migration tool supports bidirectional migration between any supported keystore types.

### Migration Tool Usage

```bash
java -cp geoserver.jar org.geoserver.security.MigrateKeystore \
  <old_keystore> <old_password> <new_keystore> <new_password> \
  [new_keystore_type] [new_provider] [old_keystore_type] [old_provider]
```

**Parameters:**
- `old_keystore`: Path to the source keystore file
- `old_password`: Password for the source keystore
- `new_keystore`: Path for the destination keystore file
- `new_password`: Password for the destination keystore
- `new_keystore_type`: Type of the destination keystore (default: JCEKS)
- `new_provider`: Provider for the destination keystore (default: KeyStoreProviderImpl default)
- `old_keystore_type`: Type of the source keystore (default: JCEKS)
- `old_provider`: Provider for the source keystore (default: null, uses default provider)

### Migration Examples

#### From BCFKS to JCEKS
```bash
java -cp geoserver.jar org.geoserver.security.MigrateKeystore \
  geoserver.bcfks old_password geoserver.jceks new_password JCEKS "" BCFKS BCFIPS
```

#### From JCEKS to BCFKS
```bash
java -cp geoserver.jar org.geoserver.security.MigrateKeystore \
  geoserver.jceks old_password geoserver.bcfks new_password BCFKS BCFIPS JCEKS
```

#### From PKCS12 to JCEKS
```bash
java -cp geoserver.jar org.geoserver.security.MigrateKeystore \
  geoserver.p12 old_password geoserver.jceks new_password JCEKS "" PKCS12
```

#### From JCEKS to PKCS12
```bash
java -cp geoserver.jar org.geoserver.security.MigrateKeystore \
  geoserver.jceks old_password geoserver.p12 new_password PKCS12 "" JCEKS
```

### Environment Variable Migration

#### From BCFKS to JCEKS
1. Set the environment variable:
   ```bash
   export GEOSERVER_KEYSTORE_TYPE=JCEKS
   ```

2. Use the migration tool:
   ```bash
   java -cp geoserver.jar org.geoserver.security.MigrateKeystore \
     geoserver.bcfks old_password geoserver.jceks new_password JCEKS "" BCFKS BCFIPS
   ```

#### From JCEKS to BCFKS
1. Set the environment variable:
   ```bash
   export GEOSERVER_KEYSTORE_TYPE=BCFKS
   ```

2. Use the migration tool:
   ```bash
   java -cp geoserver.jar org.geoserver.security.MigrateKeystore \
     geoserver.jceks old_password geoserver.bcfks new_password BCFKS BCFIPS JCEKS
   ```

## Testing

The system includes tests to verify the environment variable configuration works correctly. Run the tests with:

```bash
mvn test -Dtest=KeyStoreProviderImplTest
```

## Compatibility

- **Backward Compatibility**: Existing BCFKS keystores continue to work when `GEOSERVER_KEYSTORE_TYPE=BCFKS` is set
- **Default Behavior**: If no environment variable is set, GeoServer defaults to JCEKS
- **Test Compatibility**: Test infrastructure has been updated to support both keystore types
- **Bidirectional Migration**: The migration tool supports migration in any direction between supported keystore types

## Security Considerations

- JCEKS provides good security for most use cases
- BCFKS provides FIPS compliance for environments requiring it
- Choose the keystore type based on your security requirements
- Ensure proper backup of keystore files before migration
- The migration tool preserves all keystore entries including private keys, certificates, and secret keys 