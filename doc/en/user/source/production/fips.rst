.. _production_fips:

FIPS 140-3 Compliance
=====================

GeoServer supports FIPS 140-3 compliance through the use of BouncyCastle FIPS (BC-FIPS) cryptographic modules and FIPS-compliant keystore formats. This enables GeoServer to meet federal and enterprise security requirements.

For more information about FIPS standards, see the `NIST FIPS 140-3 documentation <https://csrc.nist.gov/pubs/fips/140-3/final>`_. For BouncyCastle FIPS certification details, see `BouncyCastle Certifications <https://www.bouncycastle.org/documentation/specification_interoperability/>`_.

Overview
--------

FIPS (Federal Information Processing Standards) 140-3 is a U.S. government computer security standard that specifies requirements for cryptographic modules. GeoServer's FIPS implementation provides:

* **BCFKS Keystore Support**: BouncyCastle FIPS KeyStore format for secure key storage
* **FIPS-Compliant Algorithms**: Cryptographic algorithms that meet FIPS 140-3 requirements
* **Backward Compatibility**: Automatic migration between JCEKS and BCFKS keystores
* **Environment Configuration**: Flexible deployment through environment variables

Enabling FIPS Mode
------------------

FIPS mode can be enabled through environment variables or system properties. **Note**: For full FIPS compliance, the operating system must also be configured for FIPS mode. GeoServer's FIPS implementation works in conjunction with OS-level FIPS settings.

Environment Variables
~~~~~~~~~~~~~~~~~~~~

Set the FIPS_MODE environment variable before starting GeoServer:

.. code-block:: bash

   # Using environment variable
   export FIPS_MODE=true
   java -jar geoserver.war

   # Or using system property
   java -DFIPS_MODE=true -jar geoserver.war

When `FIPS_MODE=true`, GeoServer automatically:
- Uses BCFKS keystore format (FIPS-compliant)
- Registers BouncyCastle FIPS provider (BCFIPS)
- Enforces FIPS-approved cryptographic algorithms

When `FIPS_MODE=false` or unset, GeoServer uses:
- JCEKS keystore format (traditional Java keystore)
- Standard Java cryptographic providers


Docker Container
~~~~~~~~~~~~~~~

For containerized deployments:

.. code-block:: bash

   docker run -d \
     -p 8080:8080 \
     -e FIPS_MODE=true \
     geoserver/geoserver:latest

Or using a custom Dockerfile:

.. code-block:: dockerfile

   FROM geoserver/geoserver:latest
   ENV FIPS_MODE=true

**Note**: The official GeoServer Docker image can be configured for FIPS mode using the FIPS_MODE environment variable. The keystore type and provider are automatically selected based on this setting.

Building with FIPS Support
~~~~~~~~~~~~~~~~~~~~~~~~~~~

GeoServer includes BC-FIPS libraries by default in all builds:

.. code-block:: bash

   # Standard build includes FIPS support
   mvn clean install

**What's Included:**
* ✅ BC-FIPS libraries for FIPS 140-2 compliance
* ✅ BCFKS keystore support for FIPS mode
* ✅ JCEKS keystore support for non-FIPS mode
* ✅ Automatic provider and keystore selection based on ``FIPS_MODE``

**Testing FIPS Mode:**

.. code-block:: bash

   # Test FIPS mode
   export FIPS_MODE=true
   java -jar geoserver.war &
   # Logs should show: "Successfully registered BouncyCastle FIPS provider"
   # Keystore: geoserver.bcfks

   # Test non-FIPS mode (uses FIPS libraries with non-FIPS algorithms)
   export FIPS_MODE=false
   java -jar geoserver.war &
   # Keystore: geoserver.jceks

The same distribution works in both modes - no rebuild required!



Keystore Configuration
---------------------

GeoServer automatically selects the appropriate keystore format based on FIPS mode:

BCFKS (BouncyCastle FIPS KeyStore)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Used automatically when ``FIPS_MODE=true``:

- **Format**: BCFKS (BouncyCastle FIPS KeyStore)
- **Provider**: BCFIPS (or BC as fallback)
- **File**: ``geoserver.bcfks``
- **Compliance**: FIPS 140-2 compliant

JCEKS (Java Cryptography Extension KeyStore)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Used automatically when ``FIPS_MODE=false`` or unset:

- **Format**: JCEKS
- **Provider**: SunJCE (default Java provider)
- **File**: ``geoserver.jceks``
- **Compatibility**: Traditional Java keystore for backward compatibility

Automatic Migration
~~~~~~~~~~~~~~~~~~

GeoServer automatically handles keystore migration when switching between FIPS and non-FIPS modes:

**Switching to FIPS mode:**

When you set ``FIPS_MODE=true``, GeoServer will:

1. Look for ``geoserver.bcfks``
2. If not found, look for ``geoserver.jceks`` (legacy)
3. If legacy found with wrong type, automatically recreate as BCFKS
4. If nothing found, create new ``geoserver.bcfks``

**Manual Migration (Optional):**

If you prefer to manually convert an existing keystore:

.. code-block:: bash

   # Backup first
   cp /path/to/data/security/geoserver.jceks /path/to/data/security/geoserver.jceks.bak

   MASTER='geoserver'  # GeoServer master password
   
   # Convert JCEKS to BCFKS
   keytool -importkeystore \
     -srckeystore /path/to/data/security/geoserver.jceks \
     -srcstoretype JCEKS \
     -srcstorepass "$MASTER" \
     -destkeystore /path/to/data/security/geoserver.bcfks \
     -deststoretype BCFKS \
     -deststorepass "$MASTER" \
     -providername BCFIPS \
     -providerclass org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider \
     -providerpath /path/to/bc-fips.jar \
     -noprompt

   # Verify
   keytool -list -keystore /path/to/data/security/geoserver.bcfks \
     -storetype BCFKS -storepass "$MASTER"

**Note**: GeoServer's automatic migration handles type detection and recreation transparently.

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

+------------------------+-------------+-------------------------------------------+
| Variable               | Default     | Description                               |
+========================+=============+===========================================+
| FIPS_MODE              | false       | Enable FIPS mode (true/false)             |
|                        |             | - true: Uses BCFKS keystore with BCFIPS   |
|                        |             | - false: Uses JCEKS keystore with SunJCE  |
+------------------------+-------------+-------------------------------------------+

Implementation Details
---------------------

Provider Registration
~~~~~~~~~~~~~~~~~~~

The FIPS implementation automatically registers the BouncyCastle FIPS provider when needed:

* **BCFIPS Provider**: Used for all BouncyCastle cryptographic operations
* **Automatic Detection**: The system automatically registers the BCFIPS provider if not already available

Property Precedence
~~~~~~~~~~~~~~~~~~

The `FIPS_MODE` setting is resolved in the following order:

1. System property `-DFIPS_MODE` (highest priority - allows runtime override)
2. Environment variable `FIPS_MODE` 
3. Default: `false` (non-FIPS mode)

This priority order allows system properties to override environment variables, which is useful for:
- Testing with different FIPS modes without changing the environment
- Per-instance configuration in containerized deployments
- Temporary overrides for debugging

Examples:

.. code-block:: bash

   # System property (highest priority - overrides environment)
   java -DFIPS_MODE=true -jar geoserver.war

   # Environment variable
   export FIPS_MODE=true
   java -jar geoserver.war

   # System property overriding environment variable
   export FIPS_MODE=false
   java -DFIPS_MODE=true -jar geoserver.war  # FIPS will be enabled

   # Default (FIPS disabled)
   java -jar geoserver.war

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