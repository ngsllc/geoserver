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

* requests BouncyCastle approved-only mode, so non-approved algorithms fail instead of running (see
  :ref:`fips_approved_only`)
* registers the BouncyCastle FIPS provider (BCFIPS) first, so it serves every algorithm it offers
* uses the BCFKS keystore format
* writes passwords with the AES-GCM ``crypt3:`` encoder and the master password file with AES-GCM, and migrates
  existing values on the first start

When ``FIPS_MODE=false`` or unset:

* uses the JCEKS keystore format
* uses the standard Java cryptographic providers; BCFIPS is appended with the lowest priority the first time
  something needs an algorithm only it offers
* offers the same password encoders as GeoServer upstream, ``crypt1:``, ``crypt2:`` and ``crypt3:``

Keystore Types
--------------

GeoServer automatically selects the keystore type based on FIPS mode:

* **BCFKS**: BouncyCastle FIPS KeyStore - automatically used when ``FIPS_MODE=true``
* **JCEKS**: Java Cryptography Extension KeyStore - automatically used when ``FIPS_MODE=false`` or unset

Providers
---------

GeoServer uses two providers:

* **BCFIPS**: BouncyCastle FIPS provider. In FIPS mode it is registered first and serves everything it offers:
  the BCFKS keystore, AES-GCM and PBKDF2 for the ``crypt3:`` encoder and the master password file, AES for URL
  parameter encryption, and the DRBG behind every ``SecureRandom``.
* **SunJCE** and the other JDK providers: used for the JCEKS keystore and everything else in non-FIPS mode, where
  BCFIPS is appended with the lowest priority.

No ``java.security`` configuration is required, but the ``bc-fips`` and ``bcpkix-fips`` JARs must be on the
classpath in both modes; they are included in the GeoServer distribution.

The ``crypt2:`` encoder and the master password files of earlier versions used ``PBEWITHSHA256AND256BITAES-BC``, a
PKCS#12 scheme that is not FIPS approved and that BCFIPS withdraws in approved-only mode. GeoServer reads those
values with its own implementation of the scheme, built on SHA-256 and AES/CBC only, and re-encrypts them; nothing
is written in that format in FIPS mode.

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

   If GeoServer fails to start with ``Failed to decrypt master password with AES-GCM or
   [PBEWITHSHA256AND256BITAES-BC, PBEWithHmacSHA256AndAES_128, PBEWithMD5AndDES]``, neither the current format nor
   any earlier one could read the master password file (``security/masterpw/default/passwd``):

   * On a FIPS-enabled operating system the usual cause is a file still encrypted with the legacy
     ``PBEWithMD5AndDES`` algorithm, which the OS blocks. Follow the
     :ref:`Password Migration <fips_password_migration>` procedure: one start on a host without OS-level FIPS
     re-encrypts the file automatically.
   * Otherwise the file is corrupt or was written by a different GeoServer. Restore ``passwd.backup`` if one
     exists, or delete the ``security`` directory to start fresh.

4. **Password Encoder Not Available (crypt1: passwords)**
   
   If you see errors about password encoders or ``crypt1:`` prefixed passwords failing in FIPS mode:
   
   * The weak password encoder (``pbePasswordEncoder``) uses ``PBEWITHMD5ANDDES`` algorithm
   * MD5 and DES algorithms are blocked on FIPS-enabled operating systems, so such values cannot be read there
   * Start GeoServer once with ``FIPS_MODE=true`` on a host without OS-level FIPS: ``crypt1:`` and ``crypt2:``
     configuration and user passwords are re-encrypted as ``crypt3:`` during that start
   
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
| Keystore (JCEKS → BCFKS)      | Yes            | Backup created, keys copied unchanged (legacy     |
|                               |                | keys are stored as ``HmacSHA256`` entries), old   |
|                               |                | file removed                                      |
+-------------------------------+----------------+---------------------------------------------------+
| Master password file          | Yes            | Re-encrypted from ``PBEWithMD5AndDES`` (or        |
|                               |                | ``PBEWithHmacSHA256AndAES_128``, used by earlier  |
|                               |                | FIPS builds) to ``PBEWITHSHA256AND256BITAES-BC``; |
|                               |                | backup kept, atomic write                         |
+-------------------------------+----------------+---------------------------------------------------+
| Configuration password        | Yes            | Switched to ``strongPbePasswordEncoder`` if the   |
| encoder                       |                | weak encoder is configured (FIPS mode only)       |
+-------------------------------+----------------+---------------------------------------------------+
| ``crypt2:`` passwords         | Not needed     | Values written by earlier GeoServer versions      |
|                               |                | stay readable; new values use the same format     |
+-------------------------------+----------------+---------------------------------------------------+
| ``crypt1:`` user/data-store   | **No**         | Readable in non-FIPS mode only. Must be           |
| passwords                     |                | re-entered via the web UI or REST API             |
+-------------------------------+----------------+---------------------------------------------------+

Passwords are encrypted with a key kept in the keystore. Keys created by earlier GeoServer versions and keys created
with FIPS support use a slightly different on-disk format; GeoServer tells them apart by the key itself, so a data
directory keeps one consistent format per key and nothing has to be re-encrypted when upgrading.

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
   * Switch the configuration password encoder to ``strongPbePasswordEncoder`` if the weak
     ``pbePasswordEncoder`` is configured, logging a warning
   * Detect the legacy JCEKS keystore and migrate it to BCFKS format, preserving the keys
   * Detect the legacy master-password encryption and re-encrypt with
     ``PBEWITHSHA256AND256BITAES-BC``, keeping a ``.backup`` copy of the original file
   * Log each migration step at INFO level

3. **Re-enter any** ``crypt1:`` **passwords** through the GeoServer web admin. Passwords already
   stored as ``crypt2:`` need no action:

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

      WARN  ... FIPS mode: the configuration password encoder 'pbePasswordEncoder' uses an algorithm that is not available in FIPS mode, switching to 'strongPbePasswordEncoder'
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

In FIPS mode the switch to the strong encoder happens automatically at startup. If you prefer to do it
before enabling FIPS mode, or on a non-FIPS host, you can update the security configuration directly:

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
* Data directories migrated by a FIPS build older than this one may hold a BCFKS keystore whose keys were
  stored as AES entries of the wrong size and cannot be read (``Provided key data wrong size for AES``).
  Restore the keystore from ``security/geoserver.jceks.backup`` (rename it to ``geoserver.jceks`` and
  delete ``geoserver.bcfks``), then restart: the migration runs again and keeps the keys readable
* The master password file is also migrated when GeoServer runs **without** ``FIPS_MODE``: the
  BouncyCastle FIPS provider is registered on demand for the master password in both modes, so a
  data directory can be prepared on a regular host and then moved to a FIPS host