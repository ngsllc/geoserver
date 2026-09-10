.. _production_fips:

FIPS 140-3 Compliance
=====================

GeoServer supports FIPS 140-3 compliance through the use of BouncyCastle FIPS (BC-FIPS) cryptographic modules and FIPS-compliant keystore formats. This enables GeoServer to meet federal and enterprise security requirements.

For more information about FIPS standards, see the `NIST FIPS 140-3 documentation <https://csrc.nist.gov/pubs/fips/140-3/final>`_. For BouncyCastle FIPS certification details, see `BouncyCastle Certifications <https://www.bouncycastle.org/documentation/specification_interoperability/>`_.

Overview
--------

FIPS (Federal Information Processing Standards) 140-3 is a U.S. government computer security standard that specifies requirements for cryptographic modules. GeoServer's FIPS implementation provides:

* **Validated module first**: the BouncyCastle FIPS provider is registered ahead of the JDK providers, so every
  algorithm it offers, random number generation included, runs inside the validated module
* **Approved-only enforcement**: BouncyCastle's approved-only mode is on, so a request for a non-approved
  algorithm fails instead of running quietly
* **Approved algorithms only**: passwords are protected with AES-256-GCM under keys derived with
  PBKDF2-HMAC-SHA256 (the ``crypt3:`` encoder), the master password file with the same, secrets are kept in a
  BCFKS keystore
* **Migration in one start**: an existing data directory (JCEKS keystore, MD5/DES master password file,
  ``crypt1:``/``crypt2:`` passwords) is converted on the first start in FIPS mode, without leaving approved-only
  mode
* **Compatible with GeoServer upstream**: the ``crypt3:`` format, the master password file layout and the way
  secrets are stored in the keystore are those of GeoServer's own FIPS module, so data directories move between the
  two

Enabling FIPS Mode
------------------

FIPS mode can be enabled through environment variables or system properties. **Note**: For full FIPS compliance, the operating system must also be configured for FIPS mode. GeoServer's FIPS implementation works in conjunction with OS-level FIPS settings.

Environment Variables
~~~~~~~~~~~~~~~~~~~~~

Set the FIPS_MODE environment variable before starting GeoServer:

.. code-block:: bash

   # Using environment variable
   export FIPS_MODE=true
   java -jar geoserver.war

   # Or using system property
   java -DFIPS_MODE=true -jar geoserver.war

When ``FIPS_MODE=true``, GeoServer automatically:

- requests BouncyCastle approved-only mode and registers the BouncyCastle FIPS provider (BCFIPS) first, before any
  other code can ask for a cipher or a random number generator
- uses the BCFKS keystore format
- writes passwords with the AES-GCM ``crypt3:`` encoder and the master password file with AES-GCM
- converts an existing data directory to those formats on the first start (see :ref:`fips_approved_only` and
  :ref:`fips_password_migration`)

When ``FIPS_MODE=false`` or unset, GeoServer uses:

- JCEKS keystore format (traditional Java keystore)
- the standard Java cryptographic providers; BCFIPS is appended with the lowest priority, so it only serves the
  algorithms no JDK provider offers
- the same password encoders as GeoServer upstream: ``crypt1:`` (weak, default for new user group services),
  ``crypt2:`` (strong) and ``crypt3:`` (AES-GCM, available but not the default)

.. _fips_approved_only:

Approved-only mode
~~~~~~~~~~~~~~~~~~

FIPS mode turns on BouncyCastle's approved-only mode for the whole JVM. In that mode the validated module refuses to
run any algorithm that is not FIPS approved: the request fails with an exception instead of quietly producing a
result. Without it the module still runs, but nothing stops non-approved cryptography, and the deployment is not
FIPS compliant.

BouncyCastle reads the switch (the ``org.bouncycastle.fips.approved_only`` system property) once, when its provider
class initializes, and applies it to every thread. GeoServer sets the property during servlet context startup, before
it loads the provider, and then verifies the mode actually took effect. If something else in the JVM initialized the
provider earlier (a servlet container configured to use BCFIPS for TLS, another web application), the check fails and
GeoServer refuses to start, telling you to set the property on the JVM command line instead:

.. code-block:: bash

   java -Dorg.bouncycastle.fips.approved_only=true -DFIPS_MODE=true -jar geoserver.war

Setting it on the command line is the safest choice in any case. Setting ``GEOSERVER_FIPS_APPROVED_ONLY=false`` (or
``-Dgeoserver.fips.approvedOnly=false``) keeps FIPS mode but leaves approved-only mode off; GeoServer logs a warning
and the status page says so. Use it only to diagnose a problem, never for a compliant deployment.

Two things a FIPS deployment should know about approved-only mode:

* HTTP Digest authentication uses MD5 by design (RFC 7616). BCFIPS does not offer MD5 in approved-only mode, so the
  request falls through to the JDK provider, which an operating system in FIPS mode blocks. Do not enable digest
  authentication in a FIPS deployment.
* PBKDF2 from a password shorter than 14 characters is refused. GeoServer's own secrets are random passwords of 32
  characters and more, so this only matters to code that derives keys from user supplied passwords.


Docker Container
~~~~~~~~~~~~~~~~

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
* ✅ BC-FIPS libraries for FIPS 140-3 compliance
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
----------------------

GeoServer automatically selects the appropriate keystore format based on FIPS mode:

BCFKS (BouncyCastle FIPS KeyStore)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Used automatically when ``FIPS_MODE=true``:

- **Format**: BCFKS (BouncyCastle FIPS KeyStore)
- **Provider**: BCFIPS
- **File**: ``geoserver.bcfks``
- **Compliance**: FIPS 140-3 compliant

JCEKS (Java Cryptography Extension KeyStore)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Used automatically when ``FIPS_MODE=false`` or unset:

- **Format**: JCEKS
- **Provider**: SunJCE (default Java provider)
- **File**: ``geoserver.jceks``
- **Compatibility**: Traditional Java keystore for backward compatibility

Automatic Migration
~~~~~~~~~~~~~~~~~~~

GeoServer automatically handles keystore migration when switching between FIPS and non-FIPS modes:

**Switching to FIPS mode:**

When you set ``FIPS_MODE=true``, GeoServer will:

1. Look for ``geoserver.bcfks``
2. If not found, look for ``geoserver.jceks`` (legacy)
3. If legacy found with wrong type, automatically migrate to BCFKS:
   
   * Creates a backup file (``.backup``) before migration
   * Migrates all keys to new format
   * If migration fails, automatically restores from backup
   * Cleans up backup after successful migration
   * Thread-safe to prevent concurrent migration conflicts

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

**Note**: GeoServer's automatic migration handles type detection and recreation transparently. The migration process:

* Creates automatic backups before migration
* Provides rollback capability if migration fails  
* Is thread-safe for concurrent server operations
* Preserves all existing keys and certificates

Verifying FIPS Mode
-------------------

Check that FIPS mode is active by examining the GeoServer logs:

.. code-block:: text

   INFO [geoserver.security] - Registered BouncyCastle FIPS provider at position 1
   INFO [geoserver.security] - FIPS mode: BouncyCastle approved-only mode is on, non-approved algorithms will fail
   INFO [geoserver.security] - Keystore migration completed: JCEKS -> BCFKS

The last line only appears the first time an existing JCEKS keystore is migrated. The Modules tab of the Server
Status page reports what is actually in force, read live from the JVM rather than from configuration:

.. code-block:: text

   FIPS mode: ENABLED
   Approved-only mode: requested, in force on this thread
   Operating system FIPS mode: yes
   Crypto provider: first
   Random source: DEFAULT (BCFIPS)
   Keystore type: BCFKS

Anything other than ``first`` for the provider means another provider answers first and does the work outside the
validated module; a random source other than ``BCFIPS`` means random bytes come from outside it; ``NOT in force on
this thread`` means approved-only mode did not take effect, see :ref:`fips_approved_only`.

**Important**: For complete FIPS compliance, ensure that the operating system is also configured for FIPS mode. GeoServer's FIPS implementation works in conjunction with OS-level FIPS settings to provide comprehensive security compliance.

Environment Variable Reference
------------------------------

+-----------------------------+-------------+--------------------------------------------------------------+
| Variable                    | Default     | Description                                                  |
+=============================+=============+==============================================================+
| FIPS_MODE                   | false       | Enable FIPS mode (true/false)                                |
|                             |             | - true: BCFIPS first, approved-only mode, BCFKS, AES-GCM    |
|                             |             | - false: JDK providers, JCEKS, upstream password encoders   |
+-----------------------------+-------------+--------------------------------------------------------------+
| GEOSERVER_FIPS_APPROVED_ONLY| true        | In FIPS mode, whether BouncyCastle approved-only mode is     |
|                             |             | requested. ``false`` runs FIPS mode without enforcement,     |
|                             |             | which is not a compliant deployment                          |
+-----------------------------+-------------+--------------------------------------------------------------+

Both can also be given as system properties (``-DFIPS_MODE=true``, ``-Dgeoserver.fips.approvedOnly=false``).

Implementation Details
----------------------

Provider Registration
~~~~~~~~~~~~~~~~~~~~~

Java hands each algorithm to the first registered provider that offers it, so the position of the BouncyCastle FIPS
provider (``BCFIPS``) decides where cryptography actually runs:

* **FIPS mode**: ``FipsRuntime.initialize()`` inserts BCFIPS at position 1 during servlet context startup, after
  requesting approved-only mode and before anything asks for a cipher or a ``SecureRandom``. Every algorithm the
  module offers (AES, GCM, PBKDF2, SHA-2, the DRBG behind ``new SecureRandom()``) then runs inside it.
* **Non-FIPS mode**: BCFIPS is appended with the lowest priority the first time something needs it, so algorithm
  names the JDK also provides keep resolving to the JDK providers, as in GeoServer upstream.

No ``java.security`` changes are needed, but the ``bc-fips`` and ``bcpkix-fips`` JARs must be on the classpath in
both modes.

Password encoders and formats
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* ``crypt3:`` (``aesGcmPasswordEncoder``): AES-256-GCM under a key derived from the keystore secret with
  PBKDF2-HMAC-SHA256 (600,000 iterations, cached). Approved, authenticated (a changed value is detected rather than
  decoded into garbage), and byte for byte the format of GeoServer upstream's encoder of the same name. The only
  encoder that writes in FIPS mode, and the default there for configuration passwords and new user group services.
* ``crypt2:`` (``strongPbePasswordEncoder``): PKCS#12 key derivation with SHA-256 and AES-256-CBC, the strong encoder
  of GeoServer upstream and of earlier FIPS builds. Not approved. In FIPS mode it is read only: existing values are
  decrypted with a built-in implementation of the scheme that needs nothing but SHA-256 and AES/CBC, so they stay
  readable in approved-only mode and get re-encrypted as ``crypt3:`` on the first start.
* ``crypt1:`` (``pbePasswordEncoder``): MD5/DES, the weak encoder. Not approved. In FIPS mode it is read only, and
  only where the JVM still offers the cipher, which an operating system in FIPS mode does not.

The master password file follows the same rule: written as AES-GCM (a 16 byte salt, then IV and ciphertext), read in
every format an earlier GeoServer used (``PBEWITHSHA256AND256BITAES-BC``, ``PBEWithHmacSHA256AndAES_128``,
``PBEWithMD5AndDES``) and re-encrypted on first use, keeping a ``.backup`` copy.

Secrets in the keystore are stored as the raw bytes of a random 40 character password, labelled ``HmacSHA256`` (the
one label both JCEKS and BCFKS accept for a key of any length), exactly as GeoServer upstream stores them. Keys
created by earlier FIPS builds, which stored a SHA-256 digest of the secret as an AES key, stay readable.

FIPS Detection Priority
~~~~~~~~~~~~~~~~~~~~~~~

GeoServer detects FIPS mode in the following order:

1. **OS-level FIPS** (highest priority - **cannot be overridden**)
   
   On Linux, GeoServer checks ``/proc/sys/crypto/fips_enabled``. If this file contains ``1``, 
   FIPS mode is enabled and cannot be disabled via environment variables or system properties.
   A warning is logged if users attempt to set ``FIPS_MODE=false`` on an OS-level FIPS system.

2. **System property** ``-DFIPS_MODE=true``
   
   Allows runtime override when OS-level FIPS is not enabled.

3. **Environment variable** ``FIPS_MODE=true``
   
   Fallback when neither OS-level FIPS nor system property is set.

4. **Default**: ``false`` (non-FIPS mode)

This priority order ensures:

- OS-level FIPS enforcement cannot be bypassed by application configuration
- System properties can override environment variables for testing
- Per-instance configuration in containerized deployments
- Temporary overrides for debugging (on non-FIPS systems)

Examples:

.. code-block:: bash

   # On OS-level FIPS system (e.g., RHEL/Rocky Linux with FIPS enabled)
   # FIPS mode is automatically enabled - no configuration needed
   java -jar geoserver.war  # FIPS enabled via OS detection

   # System property (overrides environment, but not OS-level FIPS)
   java -DFIPS_MODE=true -jar geoserver.war

   # Environment variable
   export FIPS_MODE=true
   java -jar geoserver.war

   # System property overriding environment variable
   export FIPS_MODE=false
   java -DFIPS_MODE=true -jar geoserver.war  # FIPS will be enabled

   # Default (FIPS disabled, only works on non-FIPS OS)
   java -jar geoserver.war

Migrating an Existing Deployment to OS-Level FIPS
-------------------------------------------------

If you have an existing GeoServer data directory that was created without FIPS mode
(e.g., JCEKS keystore, ``PBEWithMD5AndDES``-encrypted master password, ``crypt1:`` passwords),
you must migrate it **before** enabling OS-level FIPS. Once the OS enforces FIPS, the JVM
blocks MD5 and DES entirely, making the legacy artifacts unreadable.

The master password file is re-encrypted automatically on the first start, whether or not
``FIPS_MODE`` is set. Files written by earlier FIPS builds with ``PBEWithHmacSHA256AndAES_128``
are migrated the same way. A ``passwd.backup`` copy of the previous file is kept next to it.

See :ref:`fips_password_migration` in the Security section for the full step-by-step procedure.
The short version:

1. Disable OS-level FIPS (``sudo fips-mode-setup --disable && sudo reboot``)
2. ``export FIPS_MODE=true`` and start GeoServer — auto-migrates the keystore and the master password and
   switches a weak configuration password encoder to the strong one; ``crypt2:`` passwords keep working
3. Re-enter any ``crypt1:`` passwords via the web UI (they become ``crypt2:``)
4. Verify: ``geoserver.bcfks`` exists, ``grep -r 'crypt1:' <data-dir>/`` returns nothing
5. Stop GeoServer, re-enable OS-level FIPS (``sudo fips-mode-setup --enable && sudo reboot``)
6. Start GeoServer — FIPS mode activates automatically via ``/proc/sys/crypto/fips_enabled``

Security Considerations
-----------------------

* **Enforcement**: with approved-only mode on, the validated module refuses non-approved algorithms. This is what
  makes the compliance claim checkable; the status page shows whether it is in force. Without it (``FIPS_MODE`` with
  ``GEOSERVER_FIPS_APPROVED_ONLY=false``) nothing prevents non-approved cryptography.
* **Provider position**: only algorithms served by BCFIPS run inside the validated module. Keep it first; the status
  page reports ``behind <name>`` when it is not.
* **Key Management**: secrets live in a BCFKS keystore protected by the master password; the master password file
  is protected with AES-GCM under a key derived from a built-in constant, that is, obfuscated rather than secret,
  as in every GeoServer. Protect the file with file system permissions.
* **Reversible passwords**: configuration passwords and, by default, user group service passwords are encrypted
  reversibly (``crypt3:``), so a keystore compromise exposes them. Use the ``digest1:`` encoder for user group
  services where reversibility is not needed, as GeoServer upstream recommends.
* **HTTP Digest authentication** relies on MD5 and cannot be made approved; do not enable it.
* **OS-Level FIPS**: for a compliant deployment the operating system must also be in FIPS mode, so that the JDK's
  own providers are restricted as well. GeoServer detects it and treats ``FIPS_MODE=false`` as an error to ignore.

Troubleshooting
---------------

Common Issues
~~~~~~~~~~~~~

**FIPS mode not detected**

Check that the environment variables are set correctly and that the BouncyCastle FIPS provider is available in the classpath. Also verify that the operating system is configured for FIPS mode if full compliance is required.

**Migration failures**

Ensure that the source keystore password is correct and that the target directory is writable. The target keystore will be created automatically if it doesn't exist.

**Master password cannot be decrypted**

If GeoServer fails to start with ``Failed to decrypt master password with [PBEWITHSHA256AND256BITAES-BC,
PBEWithHmacSHA256AndAES_128, PBEWithMD5AndDES]`` on a FIPS-enabled operating system, the master password
file is still encrypted with the legacy ``PBEWithMD5AndDES`` algorithm, which the OS blocks. Follow the
:ref:`migration procedure <fips_password_migration>`: a single start on a host without OS-level FIPS
re-encrypts the file. On a non-FIPS host the same error means the file is corrupt or was written by a
different GeoServer; restore ``passwd.backup`` or delete the ``security`` directory to start fresh.

A warning ``Failed to migrate master password to PBEWITHSHA256AND256BITAES-BC`` means the file was read but
could not be rewritten (for example a read-only ``security`` directory). GeoServer keeps running with the old
file; fix the permissions so the migration can complete on the next start.

**Weak password encoder in FIPS mode**

A message ending in ``Algorithm 'PBEWITHMD5ANDDES' not available in FIPS mode`` means a component is still
configured with the weak ``pbePasswordEncoder``. The configuration password encoder is switched to the
strong encoder automatically at startup (a warning is logged), but a user/group service configured with
the weak encoder has to be changed by hand: edit ``security/usergroup/<name>/config.xml`` and set
``<passwordEncoderName>strongPbePasswordEncoder</passwordEncoderName>`` (or ``digestPasswordEncoder``),
then re-set the affected user passwords.

**Keystore key cannot be read after migration**

``BCFKS KeyStore unable to recover secret key ... Provided key data wrong size for AES`` means the keystore
was migrated by an earlier FIPS build that stored legacy keys as AES entries. Stop GeoServer, delete
``security/geoserver.bcfks``, rename ``security/geoserver.jceks.backup`` to ``geoserver.jceks`` and start
again on a host without OS-level FIPS: the migration now stores such keys as ``HmacSHA256`` entries and
they stay readable.

**Provider not found errors**

Verify that the BouncyCastle FIPS JAR files (bc-fips.jar, bcpkix-fips.jar) are in the classpath and that regular BouncyCastle providers (bcprov.jar, bcpkix.jar) are not also present.

**Package sealing violations**

If you see ``java.lang.SecurityException: sealing violation`` errors, this indicates that both regular and FIPS BouncyCastle providers are in the classpath. Remove the conflicting provider JARs.

**Keystore access denied**

Check file permissions and ensure the GeoServer process has read/write access to keystore files.

**crypt1: passwords fail after enabling FIPS**

Passwords prefixed with ``crypt1:`` use the ``PBEWITHMD5ANDDES`` algorithm which is blocked in
FIPS mode. These passwords are **not** auto-migrated. Re-enter them through the GeoServer web
admin (they will be re-saved as ``crypt2:``).

Log Analysis
~~~~~~~~~~~~

Look for these log messages to verify FIPS operation:

.. code-block:: text

   ✓ FIPS mode is active in the container
   ✓ Keystore type is set to BCFKS (FIPS-compliant) 