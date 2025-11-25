.. _production_fips:

FIPS 140-2 Compliance
=====================

GeoServer supports FIPS 140-2 compliance through the use of BouncyCastle FIPS (BC-FIPS) cryptographic modules and FIPS-compliant keystore formats. This enables GeoServer to meet federal and enterprise security requirements.

Overview
--------

FIPS (Federal Information Processing Standards) 140-2 is a U.S. government computer security standard that specifies requirements for cryptographic modules. GeoServer's FIPS implementation provides:

* **BCFKS Keystore Support**: BouncyCastle FIPS KeyStore format for secure key storage
* **FIPS-Compliant Algorithms**: Cryptographic algorithms that meet FIPS 140-2 requirements
* **Backward Compatibility**: Support for existing JCEKS keystores with automatic migration
* **Environment Configuration**: Flexible deployment through environment variables

Enabling FIPS Mode
------------------

FIPS mode can be enabled through environment variables or system properties. **Note**: For full FIPS compliance, the operating system must also be configured for FIPS mode. GeoServer's FIPS implementation works in conjunction with OS-level FIPS settings.

Environment Variables
~~~~~~~~~~~~~~~~~~~~

Set the following system property before starting GeoServer:

.. code-block:: bash

   java -Dcom.redhat.fips=true \
        -DGEOSERVER_KEYSTORE_TYPE=PKCS12 \
        -DGEOSERVER_KEYSTORE_PROVIDER=BCFIPS \
        -jar geoserver.war

**Note**: The `GEOSERVER_KEYSTORE_TYPE` and `GEOSERVER_KEYSTORE_PROVIDER` variables are optional. If not set, GeoServer will use sensible defaults:
- `GEOSERVER_KEYSTORE_TYPE`: Defaults to `JCEKS` in non-FIPS mode, `PKCS12` in FIPS mode
- `GEOSERVER_KEYSTORE_PROVIDER`: Defaults to `SunJCE` in non-FIPS mode, `BCFIPS` (or `BC`) in FIPS mode


Docker Container
~~~~~~~~~~~~~~~

For containerized deployments, you have several options:

**Option 1: Use GeoServer with FIPS Environment**
Configure GeoServer for FIPS mode:

.. code-block:: bash

   docker run -d \
     -p 8080:8080 \
     -e JAVA_OPTS="-Dcom.redhat.fips=true -DGEOSERVER_KEYSTORE_TYPE=PKCS12 -DGEOSERVER_KEYSTORE_PROVIDER=BCFIPS" \
     geoserver/geoserver:latest

**Option 2: Build Custom FIPS-Enabled Image**
If you need a dedicated FIPS-enabled image, create a custom Dockerfile:

.. code-block:: dockerfile

   FROM geoserver/geoserver:latest
   # Install BouncyCastle FIPS libraries
   # Configure FIPS mode in the container
   ENV FIPS_MODE=true
   ENV GEOSERVER_KEYSTORE_TYPE=BCFKS

**Note**: The official GeoServer Docker image can be configured for FIPS mode using environment variables as shown above. A dedicated FIPS-enabled image may be provided in future releases.

Building with FIPS Support
~~~~~~~~~~~~~~~~~~~~~~~~~~~

GeoServer now includes BC-FIPS libraries by default in all builds, providing universal FIPS compatibility:

.. code-block:: bash

   # Standard build now includes FIPS support
   mvn clean install

**What's Included:**
* ✅ BC-FIPS libraries (always included)
* ✅ Regular BouncyCastle libraries (always included)
* ✅ Runtime detection for appropriate provider selection
* ✅ Single distribution works on both FIPS and non-FIPS systems

Universal Distribution Details
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The universal distribution includes both BC-FIPS and regular BouncyCastle libraries. At runtime:

* **FIPS Mode**: Loads BC-FIPS providers when ``com.redhat.fips=true``
* **Non-FIPS Mode**: Uses regular BouncyCastle providers
* **Automatic Detection**: No manual classpath configuration needed

**How It Works:**

1. **Package Sealing**: BC-FIPS and regular BC cannot be loaded simultaneously due to package sealing restrictions

2. **Conditional Loading**: GeoServer's security framework only loads the appropriate provider:
   - ``KeyStoreProviderImpl.isFipsEnvironment()`` detects FIPS mode
   - ``GeoServerPBEPasswordEncoder.ensureProviderAvailableIfRequested()`` loads the correct provider

3. **ClassLoader Isolation**: Even though both JARs are present, only one provider is registered in the JVM

This approach leverages the existing conditional provider loading in GeoServer's security framework, ensuring compatibility across environments without manual configuration.

**Testing Universal Distribution:**

.. code-block:: bash

   # Test FIPS mode
   java -Dcom.redhat.fips=true -jar geoserver.war &
   # Logs should show: "Successfully registered BouncyCastle FIPS provider"

   # Test non-FIPS mode
   java -jar geoserver.war &
   # Logs should show: "Successfully registered standard BouncyCastle provider"

Both modes work with the same distribution - no rebuild or JAR swapping required!

**Dependency Conflicts**

BouncyCastle FIPS providers cannot coexist with regular BouncyCastle providers in the same classpath due to package sealing requirements. If you encounter errors like:

.. code-block:: text

   java.lang.SecurityException: sealing violation: can't seal package org.bouncycastle.crypto: already defined

This indicates that both regular and FIPS BouncyCastle providers are present. To resolve this:

1. **For FIPS mode**: Ensure only FIPS dependencies (`bc-fips`, `bcpkix-fips`) are in the classpath
2. **For standard mode**: Ensure only regular dependencies (`bcprov-jdk18on`, `bcpkix-jdk18on`) are in the classpath
3. **For testing**: The Maven build marks FIPS dependencies as optional to avoid conflicts

Keystore Configuration
---------------------

GeoServer supports multiple keystore types for different security requirements:

BCFKS (BouncyCastle FIPS KeyStore)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The BCFKS format provides FIPS 140-2 compliance:

.. code-block:: properties

   GEOSERVER_KEYSTORE_TYPE=BCFKS
   GEOSERVER_KEYSTORE_PROVIDER=BC

JCEKS (Java Cryptography Extension KeyStore)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Traditional Java keystore format for backward compatibility:

.. code-block:: properties

   GEOSERVER_KEYSTORE_TYPE=JCEKS
   GEOSERVER_KEYSTORE_PROVIDER=SunJCE

PKCS12
~~~~~~

Standard format for certificate and key storage. PKCS12 is included as an option because it provides a widely-supported, industry-standard format that is compatible with many tools and systems while still offering good security properties:

.. code-block:: properties

   GEOSERVER_KEYSTORE_TYPE=PKCS12
   GEOSERVER_KEYSTORE_PROVIDER=BC

Migrating existing JCEKS to PKCS12
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When moving to FIPS, convert existing ``geoserver.jceks`` to PKCS12:

.. code-block:: bash

   # backup first
   cp /path/to/data/security/geoserver.jceks /path/to/data/security/geoserver.jceks.bak

   MASTER='geoserver'  # GeoServer master password (default for local dev)
   keytool -importkeystore \
     -srckeystore /path/to/data/security/geoserver.jceks \
     -srcstoretype JCEKS \
     -srcstorepass "$MASTER" \
     -destkeystore /path/to/data/security/geoserver.pkcs12 \
     -deststoretype PKCS12 \
     -deststorepass "$MASTER" \
     -noprompt

   # verify
   keytool -list -keystore /path/to/data/security/geoserver.pkcs12 -storetype PKCS12 -storepass "$MASTER"

Optionally convert to BCFKS:

.. code-block:: bash

   keytool -importkeystore \
     -srckeystore /path/to/data/security/geoserver.jceks -srcstoretype JCEKS -srcstorepass "$MASTER" \
     -destkeystore /path/to/data/security/geoserver.bcfks -deststoretype BCFKS -deststorepass "$MASTER" -noprompt

After conversion, either set:

.. code-block:: bash

   export GEOSERVER_KEYSTORE_TYPE=PKCS12

or rely on filename-based type detection introduced in this branch. If the configured keystore is missing,
GeoServer will attempt loading legacy ``geoserver.jceks`` for backward compatibility.

Verifying FIPS Mode
------------------

Check that FIPS mode is active by examining the GeoServer logs:

.. code-block:: text

   INFO [geoserver.security] - FIPS mode enabled
   INFO [geoserver.security] - Using BCFKS keystore format
   INFO [geoserver.security] - BouncyCastle FIPS provider registered

**Important**: For complete FIPS compliance, ensure that the operating system is also configured for FIPS mode. GeoServer's FIPS implementation works in conjunction with OS-level FIPS settings to provide comprehensive security compliance.

Environment Variable Reference
-----------------------------

+------------------------+-------------+------------------+------------------+
| Variable               | Default     | Description      | Values           |
+========================+=============+==================+==================+
| FIPS_MODE              | false       | Enable FIPS mode | true, false      |
+------------------------+-------------+------------------+------------------+
| GEOSERVER_KEYSTORE_TYPE| JCEKS       | Keystore format  | BCFKS, JCEKS,    |
|                        | (PKCS12 in  |                  | PKCS12           |
|                        | FIPS mode)  |                  |                  |
+------------------------+-------------+------------------+------------------+
| GEOSERVER_KEYSTORE_    | SunJCE      | Keystore provider| BC, SunJCE       |
| PROVIDER               | (BC in      |                  |                  |
|                        | FIPS mode)  |                  |                  |
+------------------------+-------------+------------------+------------------+

Implementation Details
---------------------

Provider Registration
~~~~~~~~~~~~~~~~~~~

The FIPS implementation automatically registers BouncyCastle providers when needed:

* **BCFIPS Provider**: Used when available for FIPS-compliant operations
* **BC Provider**: Fallback provider for BouncyCastle functionality
* **Automatic Detection**: The system detects available providers and uses the most appropriate one

Property Precedence
~~~~~~~~~~~~~~~~~~

Configuration values are resolved in the following order:

1. Environment variables (highest priority)
2. System properties (same names as environment variables)
3. Default values (lowest priority)

For example, `GEOSERVER_KEYSTORE_TYPE` can be set via:
* Environment variable: `export GEOSERVER_KEYSTORE_TYPE=BCFKS`
* System property: `-DGEOSERVER_KEYSTORE_TYPE=BCFKS`
* Default: `JCEKS` (or `PKCS12` in FIPS mode)

Security Considerations
----------------------

* **Key Management**: BCFKS provides enhanced key protection compared to JCEKS
* **Algorithm Compliance**: FIPS mode ensures only approved cryptographic algorithms are used
* **Audit Requirements**: FIPS compliance may be required for government and enterprise deployments
* **Performance Impact**: FIPS-compliant algorithms may have slightly different performance characteristics
* **OS-Level FIPS**: For complete compliance, the operating system must also be configured for FIPS mode

Troubleshooting
--------------

Common Issues
~~~~~~~~~~~~

**FIPS mode not detected**

Check that the environment variables are set correctly and that the BouncyCastle FIPS provider is available in the classpath. Also verify that the operating system is configured for FIPS mode if full compliance is required.

**Migration failures**

Ensure that the source keystore password is correct and that the target directory is writable. The target keystore will be created automatically if it doesn't exist.

**Provider not found errors**

Verify that the BouncyCastle FIPS JAR files (bc-fips.jar, bcpkix-fips.jar) are in the classpath and that regular BouncyCastle providers (bcprov.jar, bcpkix.jar) are not also present.

**Package sealing violations**

If you see ``java.lang.SecurityException: sealing violation`` errors, this indicates that both regular and FIPS BouncyCastle providers are in the classpath. Remove the conflicting provider JARs.

**Keystore access denied**

Check file permissions and ensure the GeoServer process has read/write access to keystore files.

Log Analysis
~~~~~~~~~~~

Look for these log messages to verify FIPS operation:

.. code-block:: text

   ✓ FIPS mode is active in the container
   ✓ Keystore type is set to BCFKS (FIPS-compliant) 