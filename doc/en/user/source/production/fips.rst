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

Set the following environment variables before starting GeoServer:

.. code-block:: bash

   export FIPS_MODE=true
   export GEOSERVER_KEYSTORE_TYPE=BCFKS
   export GEOSERVER_KEYSTORE_PROVIDER=BC

**Note**: The `GEOSERVER_KEYSTORE_TYPE` and `GEOSERVER_KEYSTORE_PROVIDER` variables are optional. If not set, GeoServer will use sensible defaults:
- `GEOSERVER_KEYSTORE_TYPE`: Defaults to `JCEKS` in non-FIPS mode, `PKCS12` in FIPS mode
- `GEOSERVER_KEYSTORE_PROVIDER`: Defaults to `SunJCE` in non-FIPS mode, `BC` in FIPS mode

System Properties
~~~~~~~~~~~~~~~~

Alternatively, set Java system properties using the same variable names:

.. code-block:: bash

   java -Dcom.redhat.fips=true \
        -DGEOSERVER_KEYSTORE_TYPE=BCFKS \
        -DGEOSERVER_KEYSTORE_PROVIDER=BC \
        -jar geoserver.war

Docker Container
~~~~~~~~~~~~~~~

For containerized deployments, use the FIPS-enabled Docker image:

.. code-block:: bash

   docker run -d \
     -p 8080:8080 \
     -e FIPS_MODE=true \
     -e GEOSERVER_KEYSTORE_TYPE=BCFKS \
     -e GEOSERVER_KEYSTORE_PROVIDER=BC \
     geoserver-fips:latest

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

Verify that the BouncyCastle FIPS JAR files (bcprov.jar, bcpkix.jar) are in the classpath.

**Keystore access denied**

Check file permissions and ensure the GeoServer process has read/write access to keystore files.

Log Analysis
~~~~~~~~~~~

Look for these log messages to verify FIPS operation:

.. code-block:: text

   ✓ FIPS mode is active in the container
   ✓ Keystore type is set to BCFKS (FIPS-compliant) 