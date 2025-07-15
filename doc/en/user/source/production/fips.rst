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

FIPS mode can be enabled through environment variables or system properties:

Environment Variables
~~~~~~~~~~~~~~~~~~~~

Set the following environment variables before starting GeoServer:

.. code-block:: bash

   export FIPS_MODE=true
   export GEOSERVER_KEYSTORE_TYPE=BCFKS
   export GEOSERVER_KEYSTORE_PROVIDER=BC

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

Standard format for certificate and key storage:

.. code-block:: properties

   GEOSERVER_KEYSTORE_TYPE=PKCS12
   GEOSERVER_KEYSTORE_PROVIDER=BC

Migration from JCEKS to BCFKS
-----------------------------

GeoServer provides a migration utility to convert existing JCEKS keystores to FIPS-compliant BCFKS format.

Using the Migration Utility
~~~~~~~~~~~~~~~~~~~~~~~~~~

The migration utility is provided as a standalone script that uses the FIPS utilities JAR:

.. code-block:: bash

   ./migrate-keystore.sh -s source.jks -sp oldpass -t target.bcfks -tp newpass

The script automatically handles:
* Dependency checking (BouncyCastle JARs)
* File validation and permissions
* Auto-detection of keystore types and providers
* Error handling and colored output

Parameters:

* ``-s, --source``: Source keystore file path
* ``-sp, --source-password``: Source keystore password
* ``-t, --target``: Target keystore file path
* ``-tp, --target-password``: Target keystore password
* ``-st, --source-type``: Source keystore type (auto-detected if not specified)
* ``-spr, --source-provider``: Source keystore provider (auto-detected if not specified)
* ``-tt, --target-type``: Target keystore type (default: BCFKS)
* ``-tpr, --target-provider``: Target keystore provider (auto-detected if not specified)
* ``-v, --verbose``: Verbose output
* ``-h, --help``: Show help message

Automated Migration
~~~~~~~~~~~~~~~~~~

Use the provided test script for automated migration testing:

.. code-block:: bash

   ./test-fips-docker.sh

This script will:

1. Build the FIPS-enabled GeoServer container
2. Create test keystores (JCEKS and BCFKS)
3. Test migration between formats
4. Validate FIPS mode activation
5. Test security endpoints

Standalone Utilities
~~~~~~~~~~~~~~~~~~~

The FIPS utilities are provided as a separate module that is not deployed into the main GeoServer application:

* **Security**: Migration utilities are not part of the production runtime
* **Flexibility**: Can be used independently of GeoServer
* **Maintenance**: Utilities can be updated without affecting the main application

The utilities include:

* **Migration Script**: ``migrate-keystore.sh`` - User-friendly keystore migration
* **FIPS Utilities JAR**: ``fips-utils.jar`` - Core migration and validation logic
* **Test Script**: ``test-fips-docker.sh`` - Automated testing and validation

Verifying FIPS Mode
------------------

Check that FIPS mode is active by examining the GeoServer logs:

.. code-block:: text

   INFO [geoserver.security] - FIPS mode enabled
   INFO [geoserver.security] - Using BCFKS keystore format
   INFO [geoserver.security] - BouncyCastle FIPS provider registered

Environment Variable Reference
-----------------------------

+------------------------+-------------+------------------+------------------+
| Variable               | Default     | Description      | Values           |
+========================+=============+==================+==================+
| FIPS_MODE              | false       | Enable FIPS mode | true, false      |
+------------------------+-------------+------------------+------------------+
| GEOSERVER_KEYSTORE_TYPE| JCEKS       | Keystore format  | BCFKS, JCEKS,    |
|                        |             |                  | PKCS12           |
+------------------------+-------------+------------------+------------------+
| GEOSERVER_KEYSTORE_    | SunJCE      | Keystore provider| BC, SunJCE       |
| PROVIDER               |             |                  |                  |
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
* Default: `JCEKS`

Security Considerations
----------------------

* **Key Management**: BCFKS provides enhanced key protection compared to JCEKS
* **Algorithm Compliance**: FIPS mode ensures only approved cryptographic algorithms are used
* **Audit Requirements**: FIPS compliance may be required for government and enterprise deployments
* **Performance Impact**: FIPS-compliant algorithms may have slightly different performance characteristics

Troubleshooting
--------------

Common Issues
~~~~~~~~~~~~

**FIPS mode not detected**

Check that the environment variables are set correctly and that the BouncyCastle FIPS provider is available in the classpath.

**Migration failures**

Ensure that the source keystore password is correct and that the target directory is writable.

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
   ✓ Keystore provider is set to BC (BouncyCastle)
   ✓ BCFKS keystore created successfully
   ✓ Migration completed successfully

Backward Compatibility
---------------------

GeoServer maintains full backward compatibility with existing JCEKS keystores:

* Existing keystores continue to work without modification
* Automatic fallback to JCEKS when BCFKS is not available
* Migration utility supports bidirectional conversion
* No breaking changes to existing security configurations

Performance Notes
----------------

* FIPS-compliant algorithms may have different performance characteristics
* BCFKS keystore operations may be slightly slower than JCEKS
* Memory usage may be higher due to additional security checks
* Consider performance testing in your specific environment

See Also
--------

* :ref:`production_config` - Production configuration guide
* :ref:`production_container` - Container deployment guide
* :ref:`production_troubleshooting` - Troubleshooting guide 