.. _security_fips:

FIPS Compliance
===============

This section describes GeoServer's FIPS (Federal Information Processing Standards) compliance features, specifically the FIPS-compliant keystore provider.

Overview
--------

GeoServer includes a FIPS-aware keystore provider that can operate in FIPS-enabled environments. The built-in ``KeyStoreProviderImpl`` automatically detects FIPS mode and uses appropriate cryptographic providers and keystore types.

FIPS KeyStore Provider
---------------------

GeoServer's keystore provider automatically:

* Detects FIPS mode through system properties and environment variables
* Uses FIPS-compliant cryptographic providers when available
* Falls back to standard providers when FIPS providers are not available
* Configures appropriate keystore types for FIPS environments

Configuration
------------

System Properties
~~~~~~~~~~~~~~~~~~

The following system properties can be used to configure FIPS behavior:

* ``com.redhat.fips``: Set to "true" to enable FIPS mode (defined as ``FIPS_PROPERTY_NAME`` constant)
* ``GEOSERVER_KEYSTORE_TYPE``: Specify the keystore type to use
* ``GEOSERVER_KEYSTORE_PROVIDER``: Specify the keystore provider

Environment Variables
~~~~~~~~~~~~~~~~~~~~~

You can also set these as environment variables with the same names (converted to uppercase with underscores).

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
* **BC**: Standard BouncyCastle provider (optional; not available by default in FIPS mode and may be disabled by policy). Requires explicit installation and registration to be usable.
* **Default**: System default provider (fallback)

.. note::

   In FIPS mode, non-FIPS providers such as ``BC`` are often unavailable. Selecting ``BC`` without installing and registering it will cause errors like ``java.security.NoSuchProviderException: no such provider: BC``. Prefer ``BCFIPS`` unless your security policy explicitly allows the standard ``BC`` provider.

Keystore migration
------------------

When enabling FIPS, prefer PKCS12 (or BCFKS if standardizing on BouncyCastle FIPS). To migrate an existing
``geoserver.jceks``:

.. code-block:: bash

   # 1) Backup
   cp /path/to/data/security/geoserver.jceks /path/to/data/security/geoserver.jceks.bak

   # 2) Convert JCEKS -> PKCS12 (master password typically "geoserver" for local dev)
   MASTER='geoserver'
   keytool -importkeystore \
     -srckeystore /path/to/data/security/geoserver.jceks \
     -srcstoretype JCEKS \
     -srcstorepass "$MASTER" \
     -destkeystore /path/to/data/security/geoserver.pkcs12 \
     -deststoretype PKCS12 \
     -deststorepass "$MASTER" \
     -noprompt

   # 3) Verify
   keytool -list -keystore /path/to/data/security/geoserver.pkcs12 -storetype PKCS12 -storepass "$MASTER"

   # (Optional) Convert to BCFKS instead
   keytool -importkeystore \
     -srckeystore /path/to/data/security/geoserver.jceks -srcstoretype JCEKS -srcstorepass "$MASTER" \
     -destkeystore /path/to/data/security/geoserver.bcfks -deststoretype BCFKS -deststorepass "$MASTER" -noprompt

Then either set the environment to prefer the new type:

.. code-block:: bash

   export GEOSERVER_KEYSTORE_TYPE=PKCS12

Notes:

* This branch auto-detects the keystore type by filename extension and will fall back to legacy
  ``geoserver.jceks`` if the configured file is missing.
* On OS-level FIPS-enforced systems, loading JCEKS may be blocked by the JVM/provider; migrate to PKCS12/BCFKS.

Usage
-----

The FIPS keystore provider is automatically used when:

1. FIPS mode is detected through system properties or environment variables
2. The FIPS keystore provider is configured as the active keystore provider

To enable FIPS mode:

.. code-block:: bash

   # Set FIPS mode system property
   export JAVA_OPTS="-Dcom.redhat.fips=true -DGEOSERVER_KEYSTORE_TYPE=PKCS12"

   # Start GeoServer
   ./bin/startup.sh

Verification
-----------

You can verify FIPS mode is active by checking the GeoServer logs for messages like:

.. code-block:: text

   INFO - Successfully registered BouncyCastle FIPS provider
   INFO - Successfully registered standard BouncyCastle provider as fallback

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

4. **NoSuchProviderException: no such provider: BC**
   
   * Prefer using the ``BCFIPS`` provider in FIPS mode.
   * If ``BC`` is required, add the standard BouncyCastle provider JAR to the classpath and register it as a security provider (for example via ``java.security`` or programmatically), and ensure your FIPS policy permits non-FIPS providers.
   * Verify availability by checking GeoServer startup logs for registered providers or by listing providers via the Java Security API.

Debug Mode
~~~~~~~~~~

To enable debug logging for FIPS operations, add the following to your logging configuration:

.. code-block:: properties

   # Enable FIPS debug logging
   org.geoserver.security.KeyStoreProviderImpl=DEBUG

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