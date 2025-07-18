.. _security_fips:

FIPS Compliance
===============

This section describes GeoServer's FIPS (Federal Information Processing Standards) compliance features, specifically the FIPS-compliant keystore provider.

Overview
--------

GeoServer includes a FIPS-compliant keystore provider that can operate in FIPS-enabled environments. This provider automatically detects FIPS mode and uses appropriate cryptographic providers and keystore types.

FIPS KeyStore Provider
---------------------

The ``FIPSKeyStoreProvider`` extends the standard GeoServer keystore provider to provide FIPS compliance. It automatically:

* Detects FIPS mode through system properties and environment variables
* Uses FIPS-compliant cryptographic providers when available
* Falls back to standard providers when FIPS providers are not available
* Configures appropriate keystore types for FIPS environments

Configuration
------------

Environment Variables
~~~~~~~~~~~~~~~~~~~

The following environment variables can be used to configure FIPS behavior:

* ``FIPS_MODE``: Set to "true" to enable FIPS mode
* ``GEOSERVER_KEYSTORE_TYPE``: Specify the keystore type to use
* ``GEOSERVER_KEYSTORE_PROVIDER``: Specify the keystore provider

System Properties
~~~~~~~~~~~~~~~~

* ``com.redhat.fips``: Set to "true" to enable FIPS mode (Red Hat specific)

Keystore Types
-------------

In FIPS mode, the following keystore types are supported:

* **PKCS12**: Default for FIPS environments (recommended)
* **JCEKS**: Java Cryptography Extension KeyStore
* **BCFKS**: BouncyCastle FIPS KeyStore (when BouncyCastle FIPS is available)

Providers
---------

The FIPS keystore provider supports the following cryptographic providers:

* **BCFIPS**: BouncyCastle FIPS provider (preferred in FIPS mode)
* **BC**: Standard BouncyCastle provider (fallback)
* **Default**: System default provider (fallback)

Usage
-----

The FIPS keystore provider is automatically used when:

1. FIPS mode is detected through system properties or environment variables
2. The FIPS keystore provider is configured as the active keystore provider

To enable FIPS mode:

.. code-block:: bash

   # Set FIPS mode environment variable
   export FIPS_MODE=true
   
   # Set keystore type for FIPS environment
   export GEOSERVER_KEYSTORE_TYPE=PKCS12
   
   # Start GeoServer
   ./bin/startup.sh

Verification
-----------

You can verify FIPS mode is active by checking the GeoServer logs for messages like:

.. code-block:: text

   INFO - FIPS mode detected, using FIPS-compliant crypto provider
   INFO - FIPS-compliant BouncyCastle provider loaded successfully
   INFO - Setting PKCS12 as default keystore type for FIPS mode

Troubleshooting
--------------

Common Issues
~~~~~~~~~~~~

1. **FIPS Provider Not Available**
   
   If you see warnings about FIPS providers not being available, ensure that:
   
   * BouncyCastle FIPS libraries are in the classpath
   * The JVM is configured for FIPS mode if required
   * Environment variables are set correctly

2. **Keystore Creation Failures**
   
   If keystore creation fails in FIPS mode:
   
   * Verify that the specified keystore type is supported
   * Check that the cryptographic provider is available
   * Review the GeoServer logs for detailed error messages

3. **Performance Issues**
   
   FIPS-compliant cryptographic operations may be slower than standard operations:
   
   * This is normal behavior for FIPS-compliant cryptography
   * Consider using hardware acceleration if available
   * Monitor system performance and adjust resources as needed

Debug Mode
~~~~~~~~~~

To enable debug logging for FIPS operations, add the following to your logging configuration:

.. code-block:: properties

   # Enable FIPS debug logging
   org.geoserver.security.FIPSKeyStoreProvider=DEBUG

Security Considerations
---------------------

* **Password Management**: Always use strong passwords for keystores in FIPS environments
* **Key Storage**: Store cryptographic keys securely and rotate them regularly
* **Access Control**: Limit access to keystore files and configuration
* **Audit Logging**: Enable audit logging for security-related operations
* **Compliance**: Ensure all cryptographic operations meet your organization's compliance requirements

Compliance Standards
-------------------

The FIPS keystore provider is designed to support:

* **FIPS 140-2**: Federal Information Processing Standards
* **FIPS 140-3**: Updated FIPS standards (when available)
* **Common Criteria**: International security standards
* **NIST Guidelines**: National Institute of Standards and Technology recommendations

For specific compliance requirements, consult your organization's security policies and the relevant standards documentation. 