.. _security_fips:

FIPS Compliance
===============

This section describes GeoServer's FIPS (Federal Information Processing Standards) compliance features, specifically the FIPS-compliant keystore provider.

Overview
--------

GeoServer includes a FIPS-aware keystore provider that can operate in FIPS-enabled environments. The built-in ``KeyStoreProviderImpl`` automatically detects FIPS mode using the following priority:

1. **OS-level FIPS**: Checks ``/proc/sys/crypto/fips_enabled`` on Linux (cannot be overridden)
2. **System property**: ``-DFIPS_MODE=true``
3. **Environment variable**: ``FIPS_MODE=true``

On systems with OS-level FIPS enabled, GeoServer automatically operates in FIPS mode without any additional configuration. The ``FIPS_MODE`` setting cannot disable FIPS on these systems.

FIPS KeyStore Provider
---------------------

GeoServer's keystore provider automatically:

* Detects OS-level FIPS mode via ``/proc/sys/crypto/fips_enabled`` (highest priority, cannot be overridden)
* Detects FIPS mode through system properties and environment variables (when OS-level FIPS is not enabled)
* Uses FIPS-compliant cryptographic providers when available
* Falls back to standard providers when FIPS providers are not available
* Configures appropriate keystore types for FIPS environments

Configuration
------------

Environment Variable
~~~~~~~~~~~~~~~~~~~~

FIPS mode is controlled by a single environment variable:

* ``FIPS_MODE``: Set to "true" to enable FIPS mode, "false" or unset for non-FIPS mode

This can also be set as a system property: ``-DFIPS_MODE=true``

When ``FIPS_MODE=true``, GeoServer automatically:
* Uses BCFKS keystore format
* Registers BouncyCastle FIPS provider (BCFIPS)
* Enforces FIPS-approved cryptographic algorithms

When ``FIPS_MODE=false`` or unset:
* Uses JCEKS keystore format
* Uses standard Java cryptographic providers

Keystore Types
-------------

GeoServer automatically selects the keystore type based on FIPS mode:

* **BCFKS**: BouncyCastle FIPS KeyStore - automatically used when ``FIPS_MODE=true``
* **JCEKS**: Java Cryptography Extension KeyStore - automatically used when ``FIPS_MODE=false`` or unset

Providers
---------

The FIPS keystore provider uses:

* **BCFIPS**: BouncyCastle FIPS provider (used in FIPS mode)
* **SunJCE**: Java default provider (used in non-FIPS mode)

The appropriate provider is automatically selected based on the ``FIPS_MODE`` setting.

Automatic Keystore Migration
----------------------------

GeoServer automatically handles keystore migration when switching to FIPS mode. When you set ``FIPS_MODE=true``, GeoServer will:

1. Look for ``geoserver.bcfks``
2. If not found, look for ``geoserver.jceks`` (legacy)
3. If legacy found with wrong type, automatically recreate as BCFKS
4. If nothing found, create new ``geoserver.bcfks``

Manual Migration (Optional)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you prefer to manually convert an existing keystore to BCFKS:

.. code-block:: bash

   # 1) Backup
   cp /path/to/data/security/geoserver.jceks /path/to/data/security/geoserver.jceks.bak

   # 2) Convert JCEKS to BCFKS
   MASTER='geoserver'  # GeoServer master password
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

   # 3) Verify
   keytool -list -keystore /path/to/data/security/geoserver.bcfks -storetype BCFKS -storepass "$MASTER"

Notes:

* GeoServer's automatic migration handles keystore type detection and recreation transparently
* On OS-level FIPS-enforced systems, loading JCEKS may be blocked; GeoServer will automatically create BCFKS

Usage
-----

The FIPS keystore provider is automatically activated when FIPS mode is enabled.

To enable FIPS mode:

.. code-block:: bash

   # Using environment variable
   export FIPS_MODE=true
   ./bin/startup.sh

   # Or using system property
   export JAVA_OPTS="-DFIPS_MODE=true"
   ./bin/startup.sh

   # Or inline
   FIPS_MODE=true ./bin/startup.sh

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

3. **Password Encoder Not Available (crypt1: passwords)**
   
   If you see errors about password encoders or ``crypt1:`` prefixed passwords failing in FIPS mode:
   
   * The weak password encoder (``pbePasswordEncoder``) uses ``PBEWITHMD5ANDDES`` algorithm
   * MD5 and DES algorithms are blocked on FIPS-enabled operating systems
   * You must migrate passwords from ``crypt1:`` to ``crypt2:`` format before enabling FIPS mode
   
   See the :ref:`Password Migration <fips_password_migration>` section below for instructions.

4. **Performance Issues**
   
   FIPS-compliant cryptographic operations may be slower than standard operations:
   
   * This is normal behavior for FIPS-compliant cryptography
   * Consider using hardware acceleration if available
   * Monitor system performance and adjust resources as needed


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

.. _fips_password_migration:

Password Migration for FIPS
---------------------------

When running on a FIPS-enabled operating system (such as Rocky Linux 9 with FIPS mode enabled), the weak password encoder 
(``pbePasswordEncoder``) that uses the ``PBEWITHMD5ANDDES`` algorithm is **not available** because MD5 and DES algorithms 
are blocked at the OS level.

**Understanding Password Prefixes:**

* ``crypt1:`` - Passwords encoded with weak ``PBEWITHMD5ANDDES`` algorithm (NOT FIPS-compliant)
* ``crypt2:`` - Passwords encoded with strong ``PBEWITHSHA256AND256BITAES-BC`` algorithm (FIPS-compliant)

**Migration Steps (Recommended - Auto-Migration):**

The simplest approach is to use GeoServer's automatic migration feature:

1. **Temporarily disable OS-level FIPS** (e.g., remove ``fips=1`` from kernel parameters and reboot)

2. **Set the FIPS_MODE environment variable**:

   .. code-block:: bash
   
      export FIPS_MODE=true

3. **Restart GeoServer** - it will automatically:
   
   * Migrate the keystore from JCEKS to BCFKS format
   * Create backups of existing files before migration
   * Update password encoders to use FIPS-compliant algorithms

4. **Unset FIPS_MODE** (optional, since OS-level FIPS will take precedence):

   .. code-block:: bash
   
      unset FIPS_MODE

5. **Re-enable OS-level FIPS and reboot** - GeoServer will now run in FIPS mode using the migrated configuration

**Manual Migration (Alternative):**

If you prefer manual control, you can update the security configuration directly:

1. Edit ``<data-dir>/security/config.xml`` and change:
   
   .. code-block:: xml
   
      <configPasswordEncrypterName>pbePasswordEncoder</configPasswordEncrypterName>
   
   To:
   
   .. code-block:: xml
   
      <configPasswordEncrypterName>strongPbePasswordEncoder</configPasswordEncrypterName>

2. Re-encrypt existing passwords by re-saving data store connections through the GeoServer web UI.

3. Verify migration by checking that password fields use ``crypt2:`` prefix instead of ``crypt1:``.

**Important Notes:**

* New GeoServer data directories created in FIPS mode automatically use the strong password encoder
* Attempting to use the weak password encoder in FIPS mode will result in a startup error
* There is no automatic migration of ``crypt1:`` passwords - they must be re-entered 