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
----------------------

GeoServer's keystore provider automatically:

* Detects OS-level FIPS mode via ``/proc/sys/crypto/fips_enabled`` (highest priority, cannot be overridden)
* Detects FIPS mode through system properties and environment variables (when OS-level FIPS is not enabled)
* Uses FIPS-compliant cryptographic providers when available
* Falls back to standard providers when FIPS providers are not available
* Configures appropriate keystore types for FIPS environments

Configuration
-------------

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
* Uses standard Java cryptographic providers for the keystore
* Still registers the BouncyCastle FIPS provider on demand, because the master password file, ``crypt2:``
  passwords and URL parameter encryption always use the FIPS algorithm (see below)

Keystore Types
--------------

GeoServer automatically selects the keystore type based on FIPS mode:

* **BCFKS**: BouncyCastle FIPS KeyStore - automatically used when ``FIPS_MODE=true``
* **JCEKS**: Java Cryptography Extension KeyStore - automatically used when ``FIPS_MODE=false`` or unset

Providers
---------

GeoServer uses two providers:

* **BCFIPS**: BouncyCastle FIPS provider. Used for the BCFKS keystore in FIPS mode, and in **both** modes for the
  strong password encoder (``crypt2:``), the encrypted master password file and URL parameter encryption. These
  all use ``PBEWITHSHA256AND256BITAES-BC``, an algorithm name that only BCFIPS registers.
* **SunJCE**: Java default provider. Used for the JCEKS keystore in non-FIPS mode.

BCFIPS is registered automatically the first time it is needed, so no ``java.security`` configuration is
required. It is appended with the lowest priority, so algorithms the JDK also provides keep resolving to the
JDK providers. The ``bc-fips`` and ``bcpkix-fips`` JARs must therefore be on the classpath in both modes; they
are included in the GeoServer distribution.

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
------------

You can verify FIPS mode is active by checking the GeoServer logs for messages like:

.. code-block:: text

   INFO - Successfully registered BouncyCastle FIPS provider
   INFO - Successfully registered standard BouncyCastle provider as fallback

Troubleshooting
---------------

Common Issues
~~~~~~~~~~~~~

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

3. **Master Password Cannot Be Decrypted**

   If GeoServer fails to start with ``Failed to decrypt master password with [PBEWITHSHA256AND256BITAES-BC,
   PBEWithHmacSHA256AndAES_128, PBEWithMD5AndDES]``, none of the known algorithms could read the master password
   file (``security/masterpw/default/passwd``):

   * On a FIPS-enabled operating system the usual cause is a file still encrypted with the legacy
     ``PBEWithMD5AndDES`` algorithm, which the OS blocks. Follow the
     :ref:`Password Migration <fips_password_migration>` procedure: one start on a host without OS-level FIPS
     re-encrypts the file automatically.
   * Otherwise the file is corrupt or was written by a different GeoServer. Restore ``passwd.backup`` if one
     exists, or delete the ``security`` directory to start fresh.

4. **Password Encoder Not Available (crypt1: passwords)**
   
   If you see errors about password encoders or ``crypt1:`` prefixed passwords failing in FIPS mode:
   
   * The weak password encoder (``pbePasswordEncoder``) uses ``PBEWITHMD5ANDDES`` algorithm
   * MD5 and DES algorithms are blocked on FIPS-enabled operating systems
   * You must migrate passwords from ``crypt1:`` to ``crypt2:`` format before enabling FIPS mode
   
   See the :ref:`Password Migration <fips_password_migration>` section below for instructions.

5. **Performance Issues**
   
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
-----------------------

* **Password Management**: Always use strong passwords for keystores in FIPS environments
* **Key Storage**: Store cryptographic keys securely and rotate them regularly
* **Access Control**: Limit access to keystore files and configuration
* **Audit Logging**: Enable audit logging for security-related operations
* **Compliance**: Ensure all cryptographic operations meet your organization's compliance requirements

Compliance Standards
--------------------

The FIPS keystore provider is designed to support:

* **FIPS 140-2**: Federal Information Processing Standards
* **FIPS 140-3**: Updated FIPS standards (when available)
* **Common Criteria**: International security standards
* **NIST Guidelines**: National Institute of Standards and Technology recommendations

For specific compliance requirements, consult your organization's security policies and the relevant standards documentation.

.. _fips_password_migration:

Migrating an Existing Data Directory to OS-Level FIPS
-----------------------------------------------------

When running on a FIPS-enabled operating system (such as RHEL 9, Rocky Linux 9, or Fedora with
``fips-mode-setup --enable``), the JVM blocks non-FIPS algorithms at the provider level.
GeoServer must complete its data-directory migration **before** OS-level FIPS is enforced,
because some legacy formats (JCEKS keystore, ``PBEWithMD5AndDES`` master-password encryption)
cannot be read once MD5 and DES are blocked.

**Understanding Password Prefixes:**

* ``crypt1:`` — Passwords encoded with weak ``PBEWITHMD5ANDDES`` algorithm (NOT FIPS-compliant)
* ``crypt2:`` — Passwords encoded with strong ``PBEWITHSHA256AND256BITAES-BC`` algorithm (FIPS-compliant,
  provided by the BouncyCastle FIPS provider)

**What auto-migrates and what does not:**

+-------------------------------+----------------+---------------------------------------------------+
| Artifact                      | Auto-migrated? | Details                                           |
+===============================+================+===================================================+
| Keystore (JCEKS → BCFKS)      | Yes            | Backup created, keys copied, old file removed     |
+-------------------------------+----------------+---------------------------------------------------+
| Master password file          | Yes            | Re-encrypted from ``PBEWithMD5AndDES`` (or        |
|                               |                | ``PBEWithHmacSHA256AndAES_128``, used by earlier  |
|                               |                | FIPS builds) to ``PBEWITHSHA256AND256BITAES-BC``; |
|                               |                | backup kept, atomic write                         |
+-------------------------------+----------------+---------------------------------------------------+
| ``crypt1:`` user/data-store   | **No**         | Must be re-entered via the web UI or REST API     |
| passwords                     |                | after migration                                   |
+-------------------------------+----------------+---------------------------------------------------+

Migration Steps (Recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Disable OS-level FIPS** so the JVM can still load legacy algorithms:

   .. code-block:: bash

      # RHEL / Rocky Linux / Fedora
      sudo fips-mode-setup --disable
      sudo reboot

      # Verify FIPS is off
      cat /proc/sys/crypto/fips_enabled   # should print 0

2. **Set the FIPS_MODE environment variable** and start GeoServer:

   .. code-block:: bash

      export FIPS_MODE=true
      ./bin/startup.sh          # or however you launch GeoServer

   On startup GeoServer will:

   * Register the BouncyCastle FIPS provider (BCFIPS)
   * Detect the legacy JCEKS keystore and migrate it to BCFKS format
   * Detect the legacy master-password encryption and re-encrypt with
     ``PBEWITHSHA256AND256BITAES-BC``, keeping a ``.backup`` copy of the original file
   * Log each migration step at INFO level

3. **Re-enter any** ``crypt1:`` **passwords** through the GeoServer web admin:

   * Data store connection passwords
   * OGC service credentials
   * Any other stored passwords showing the ``crypt1:`` prefix

   Re-saving them while ``FIPS_MODE=true`` will encode them as ``crypt2:``.

4. **Verify the migration** before re-enabling OS FIPS:

   .. code-block:: bash

      # Keystore should be BCFKS
      ls <data-dir>/security/geoserver.bcfks

      # No crypt1: references should remain in XML files
      grep -r 'crypt1:' <data-dir>/

   Check the GeoServer logs for:

   .. code-block:: text

      INFO  ... Master password was encrypted with PBEWithMD5AndDES, migrating to PBEWITHSHA256AND256BITAES-BC
      INFO  ... Successfully migrated master password to PBEWITHSHA256AND256BITAES-BC
      INFO  ... Keystore migration completed: JCEKS -> BCFKS

5. **Stop GeoServer**, then **re-enable OS-level FIPS** and reboot:

   .. code-block:: bash

      ./bin/shutdown.sh
      sudo fips-mode-setup --enable
      sudo reboot

      # Verify FIPS is on
      cat /proc/sys/crypto/fips_enabled   # should print 1

6. **Start GeoServer** — no ``FIPS_MODE`` variable is needed because OS-level FIPS
   is detected automatically via ``/proc/sys/crypto/fips_enabled``:

   .. code-block:: bash

      ./bin/startup.sh

   GeoServer registers the BCFIPS provider at startup and logs:

   .. code-block:: text

      INFO  ... Successfully registered BouncyCastle FIPS provider

   The Modules tab of the Server Status page shows the ``FIPS Mode`` module with
   ``FIPS Mode: ENABLED`` and ``Keystore Type: BCFKS``.

Manual Migration (Alternative)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
* The ``bc-fips`` and ``bcpkix-fips`` JARs **must** be on the classpath for FIPS mode to work
* There is no automatic migration of ``crypt1:`` passwords — they must be re-entered
* The master password file is also migrated when GeoServer runs **without** ``FIPS_MODE``: the
  BouncyCastle FIPS provider is registered on demand for the master password in both modes, so a
  data directory can be prepared on a regular host and then moved to a FIPS host