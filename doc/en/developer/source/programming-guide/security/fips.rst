.. _security_fips_dev:

FIPS Development
================

This section provides information for developers working with FIPS-compliant features in GeoServer.

FIPS-aware keystore handling
----------------------------

GeoServer's ``KeyStoreProviderImpl`` detects FIPS mode using the following priority:

1. **OS-level FIPS**: Checks ``/proc/sys/crypto/fips_enabled`` on Linux (cannot be overridden)
2. **System property**: ``-DFIPS_MODE=true``  
3. **Environment variable**: ``FIPS_MODE=true``

Based on this detection, it automatically selects the appropriate keystore type: BCFKS for FIPS mode, JCEKS for 
non-FIPS mode. It also automatically migrates keystores between formats when FIPS mode changes, infers the 
keystore type from the filename extension, and falls back to legacy keystore files if the configured file is 
not present.

.. note::
   On systems with OS-level FIPS enabled, attempting to set ``FIPS_MODE=false`` will log a warning and 
   FIPS mode will remain enabled. OS-level FIPS cannot be overridden by application configuration.

Key Features
~~~~~~~~~~~~

* **Automatic FIPS Detection**: Detects OS-level FIPS first (highest priority, immutable), then system properties, then environment variables
* **Filename Inference**: Infers keystore type from extension
* **Legacy Fallback**: Falls back to legacy keystore files when the configured one is missing
* **Provider Fallback**: Registers/uses BouncyCastle providers for BCFKS when necessary
* **Automatic Migration**: Migrates keystores between JCEKS and BCFKS formats with automatic backup/rollback
* **Thread Safety**: Synchronized keystore operations prevent race conditions during concurrent access

Implementation Details
~~~~~~~~~~~~~~~~~~~~~~

Building with FIPS Support
^^^^^^^^^^^^^^^^^^^^^^^^^^

GeoServer includes BC-FIPS libraries by default. No special profiles are needed.

**Standard Build:**
.. code-block:: bash

   # BC-FIPS is included by default
   mvn clean install

**What's Included:**
* BC-FIPS libraries for FIPS 140-3 compliance
* BCFKS and JCEKS keystore support

**Technical Implementation:**

* ``KeyStoreProviderImpl.isFipsMode()`` detects FIPS mode by checking:
  
  1. ``isOsFipsEnabled()`` - reads ``/proc/sys/crypto/fips_enabled`` (immutable)
  2. System property ``FIPS_MODE``
  3. Environment variable ``FIPS_MODE``

* ``FipsRuntime`` owns the process wide state: ``initialize()`` runs first in ``GeoserverInitStartupListener``,
  requests approved-only mode, inserts BCFIPS at position 1 and verifies the mode took effect;
  ``registerProvider()`` is the single registration point (first in FIPS mode, appended otherwise) and
  ``secureRandom()`` the single random source (the BCFIPS DRBG in FIPS mode, asked for by name).
  ``KeyStoreProviderImpl.ensureBcFipsProviderRegistered()`` delegates to it
* Automatic keystore type selection: BCFKS (FIPS) or JCEKS (non-FIPS)

Approved-only mode
^^^^^^^^^^^^^^^^^^

Two facts about BC-FIPS decide the design, both verified against bc-fips 2.1.2 (``FipsApprovedOnlyTest`` pins the
consequences):

* ``org.bouncycastle.fips.approved_only`` is read once, when the provider class initializes, and applies to every
  thread. Set later it reaches no thread at all. The per-thread ``CryptoServicesRegistrar.setApprovedOnlyMode`` is
  not inherited by child threads and can never be undone. So the property has to be set before anything loads a
  BouncyCastle class, which is what ``FipsRuntime.initialize()`` does, and migration of existing data has to work
  *inside* approved-only mode.
* In approved-only mode BC-FIPS offers no password based cipher at all (the whole ``PBEWITH*`` family is gone) and
  refuses PBKDF2 from passwords under 112 bits.

Everything GeoServer writes therefore uses PBKDF2-HMAC-SHA256 and AES-GCM, and everything it needs to read from
earlier versions is decrypted without asking a provider for a non-approved cipher.

Password encoders and formats
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**``crypt3:``, ``GeoServerAesGcmPasswordEncoder`` / ``AesGcmCipher``.** Key = PBKDF2-HMAC-SHA256(secret, salt =
SHA-256(secret)[0..16], 600,000 iterations, 256 bit); value = Base64(IV(12) || AES-256-GCM ciphertext and tag). The
salt is a digest of the secret because the secrets are unique 40 character random passwords and a random salt would
have to be stored next to them; the class documents why this must never be used with a human chosen password. The
derived key is cached in ``KeyStoreProviderImpl.getDerivedKey`` and dropped whenever the keystore changes. Parameters,
layout and the bean name ``aesGcmPasswordEncoder`` are those of GeoServer upstream (geoserver/geoserver#9855);
``AesGcmCipherTest`` holds a key and a ciphertext produced by upstream's implementation. ``matches`` and
``isPasswordValid`` return ``false`` for a value that does not decrypt (corrupt, or another key) instead of throwing,
and compare in constant time.

**``crypt2:`` and ``crypt1:``, ``GeoServerPBEPasswordEncoder``.** Read only in FIPS mode; ``encodePassword`` throws
an ``IllegalStateException`` naming ``crypt3``. ``crypt2:`` values (PKCS#12 SHA-256, AES-256-CBC; jasypt layout
``salt(16) || [16 ignored bytes when the writer had an IV generator] || ciphertext``) are decrypted by
``Pkcs12Pbe``, an implementation of RFC 7292 appendix B over ``MessageDigest`` SHA-256 and ``AES/CBC/PKCS5Padding``.
It was validated against 400 values written by jasypt on BC-FIPS and against a value written by GeoServer upstream
with stock BouncyCastle (``LegacyPasswordFixtures.CRYPT2``); ``Pkcs12PbeTest`` pins both layouts. ``crypt1:`` goes
through jasypt and the JDK's ``PBEWithMD5AndDES``, which exists only where the operating system is not in FIPS mode.
In non-FIPS mode both encoders still write, exactly like upstream.

**Keystore secrets.** ``KeyStoreProviderImpl.setSecretKey`` and ``addInitialKeys`` store the raw bytes of the random
password under the ``HmacSHA256`` label (``LEGACY_SECRET_KEY_ALGORITHM``), the one label JCEKS and BCFKS both accept
for any length; this is how upstream stores them, so ``getDerivedKey`` hands the characters of those bytes to the
derivation and the two produce the same ``crypt3`` keys. Keys created by earlier FIPS builds are SHA-256 derived AES
keys; ``getDerivedKey`` hands those over as Base64 instead, and ``GeoServerPBEPasswordEncoder.isLegacyKey`` still
selects the matching ``crypt2`` layout for them. Never alter key bytes.

**Boot migration.** In FIPS mode ``GeoServerSecurityManager.reload()`` runs, in order:
``ensureFipsCompatibleConfigPasswordEncoder`` (before ``init()``: a ``crypt1``/``crypt2`` configuration encoder is
switched to ``aesGcmPasswordEncoder`` in ``config.xml``), then after ``init()``
``updateConfigurationFilesWithEncryptedFields`` (re-encrypts store and security configuration passwords) and
``ensureFipsCompatibleUserGroupEncoders`` (for every writable user group service on a PBE encoder: decode each user
password with the old encoder, encode with ``crypt3``, ``updateUser``, ``store``, switch the service configuration;
a read only service is reported). All of it runs in approved-only mode. ``FipsBootMigrationTest`` stages a legacy
data directory, ``crypt2`` user passwords included, and checks every step.

**Master password file, ``URLMasterPasswordProvider``.** Written as ``salt(16) || AesGcmCipher.encrypt(PBKDF2(key(),
salt), password)``, the layout of upstream's ``AesGcmMasterPasswordProvider``; the derived key is cached per salt.
``decode()`` tries AES-GCM first (the tag rules out a false match), then ``KNOWN_PBE_ALGORITHMS`` in order:
``PBEWITHSHA256AND256BITAES-BC`` through ``Pkcs12Pbe``, then the SunJCE ``PBEWithHmacSHA256AndAES_128`` and
``PBEWithMD5AndDES`` through jasypt. A file readable only through a fallback is re-encrypted through a temp file, a
``.backup`` copy and an atomic rename. When adding a format, keep the previous reader and add a fixture to
``JasyptDecodeTest`` or ``URLMasterPasswordProviderTest``.

**URL parameter encryption.** ``GeoServerApplication`` installs ``KeyInSessionAesCryptFactory`` (a port of upstream's):
an AES-256 key per session from ``KeyGenerator`` seeded by ``FipsRuntime.secureRandom()``, and ``AesCbcCrypt`` with an
IV derived from the key. The IV is fixed per session on purpose, Wicket compares a re-rendered URL with the requested
one and a random IV would send the browser in a redirect loop; the class documents what that costs.

**Randomness.** ``FipsRandomSaltGenerator``, ``FipsRandomIvGenerator`` and Wicket's ``FipsSecureRandomSupplier`` all
draw from ``FipsRuntime.secureRandom()``. Do not call ``new SecureRandom()`` in FIPS aware code: with the provider
appended it comes from ``SUN``, which is exactly what the status page's ``Random source`` line exists to catch.

Core Implementation
^^^^^^^^^^^^^^^^^^^

The core keystore provider implements the following key methods:

.. code-block:: java

   KeyStoreProviderImpl provider = new KeyStoreProviderImpl();
   provider.setSecurityManager(securityManager);
   provider.refreshKeyStoreType();

Configuration
~~~~~~~~~~~~~

Configure via a single environment variable:

* **FIPS Mode**: ``FIPS_MODE=true`` (or system property ``-DFIPS_MODE=true``)

When ``FIPS_MODE=true``:
* Keystore Type: BCFKS (automatic)
* Provider: BCFIPS (automatic)

When ``FIPS_MODE=false`` or unset:
* Keystore Type: JCEKS (automatic)
* Provider: SunJCE (default) for the keystore; BCFIPS is still registered on demand for password-based
  encryption

Testing FIPS behavior
~~~~~~~~~~~~~~~~~~~~~

Unit tests cover default type selection and provider resolution. ``JasyptDecodeTest`` (``gs-main``) checks
the algorithm round trips, decodes fixtures written with the legacy and previous algorithms and runs the
decode chain with ``FIPS_MODE=true``; ``URLMasterPasswordProviderTest`` (``security-tests``) verifies that
legacy and previous-algorithm master password files are migrated with a backup and no leftover temp files.
Note that the system test harness cannot boot with ``FIPS_MODE=true`` set for the whole JVM, so FIPS-mode
behaviour is covered by unit tests and by ``FipsModeSwitchingIntegrationTest``, which toggles the property
per test. For manual checks, set ``FIPS_MODE=true`` (or ``-DFIPS_MODE=true``) and verify BCFKS keystore usage
in the logs.

Integration with Security Framework
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use ``GeoServerSecurityManager#getKeyStoreProvider()`` to access the active provider; keystore
type and provider are resolved internally based on configuration and environment.

Development Guidelines
----------------------

When developing FIPS-compliant features:

1. **Use FIPS-Approved Algorithms**: AES (GCM or CBC), SHA-2, HMAC, PBKDF2 with a password of at least 14 bytes.
   No password based cipher (``PBEWith*``), no MD5, no DES or 3DES. If in doubt, run it on an approved-only thread
   the way ``FipsApprovedOnlyTest`` does; BC-FIPS will tell you.
2. **Test in FIPS Mode**: ``FipsApprovedOnlyTest`` runs the approved-only checks in every build; ``FipsBootMigrationTest``
   covers the migration of an existing data directory. Test on a host with the OS in FIPS mode before a release
3. **Handle Provider Failures**: Implement proper fallback mechanisms
4. **Log Security Events**: Log security-related events for audit purposes
5. **Validate Inputs**: Validate all cryptographic inputs

Example: Creating a FIPS-Compliant Service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: java

   KeyStoreProvider provider = securityManager.getKeyStoreProvider();
   String defaultType = KeyStoreProviderImpl.getKeyStoreType();

Keystore Migration and Safety
-----------------------------------

Automatic Migration Process
~~~~~~~~~~~~~~~~~~~~~~~~~~~

GeoServer automatically migrates keystores when switching between FIPS and non-FIPS modes. The migration process includes:

**Backup and Rollback:**

* Before migration, creates a ``.backup`` file (e.g., ``geoserver.jceks.backup``)
* If migration fails, automatically restores from backup
* After successful migration, cleans up the backup file
* Original keystore is deleted only after successful migration

**Thread Safety:**

The following methods are synchronized to prevent race conditions:

* ``reloadKeyStore()`` - Prevents concurrent reload attempts
* ``assertActivatedKeyStore()`` - Ensures single-threaded migration
* ``storeKeyStore()`` - Prevents concurrent writes

This synchronization ensures that:

* Multiple threads can safely access the keystore provider
* Only one migration occurs at a time
* No data corruption from concurrent operations

**Provider Validation:**

When registering the BouncyCastle FIPS provider, the system validates:

* BCFKS keystore type is supported
* Required algorithms (SHA-256) are available
* Provider is properly initialized before use

**Example Migration Flow:**

.. code-block:: text

   1. Detect keystore type mismatch (JCEKS found, BCFKS expected)
   2. Create geoserver.jceks.backup
   3. Load old JCEKS keystore
   4. Create new BCFKS keystore
   5. Copy all keys (normalized for compatibility)
   6. Write new geoserver.bcfks
   7. Delete old geoserver.jceks
   8. Clean up geoserver.jceks.backup
   9. Update resource cache to point to new file

If step 6 fails, the backup is automatically restored.

Manual Migration (Optional)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

For manual migration to BCFKS:

.. code-block:: bash

   keytool -importkeystore \
     -srckeystore /path/to/data/security/geoserver.jceks -srcstoretype JCEKS -srcstorepass "$MASTER" \
     -destkeystore /path/to/data/security/geoserver.bcfks -deststoretype BCFKS -deststorepass "$MASTER" -noprompt

Debugging FIPS Issues
---------------------

Common debugging techniques for FIPS-related issues:

1. **Enable Debug Logging**:

   .. code-block:: properties

      org.geoserver.security.KeyStoreProviderImpl=DEBUG

2. **Check Provider Availability**:

   .. code-block:: java

      Provider[] providers = Security.getProviders();
      for (Provider p : providers) {
          System.out.println(p.getName() + " - " + p.getVersion());
      }

3. **Verify FIPS Mode**:

   .. code-block:: java

      boolean fipsMode = KeyStoreProviderImpl.isFipsMode();
      System.out.println("FIPS Mode: " + fipsMode);

4. **Test Keystore Operations**:

   .. code-block:: java

      try {
          String keystoreType = KeyStoreProviderImpl.getKeyStoreType(); // BCFKS or JCEKS
          KeyStore keystore = KeyStore.getInstance(keystoreType);
          keystore.load(null, "password".toCharArray());
          System.out.println("Keystore (" + keystoreType + ") created successfully");
      } catch (Exception e) {
          System.err.println("Keystore creation failed: " + e.getMessage());
      }

Performance Considerations
--------------------------

FIPS-compliant cryptographic operations may have performance implications:

* **Slower Operations**: FIPS-compliant algorithms may be slower than standard algorithms
* **Memory Usage**: FIPS providers may use more memory
* **CPU Usage**: Cryptographic operations may use more CPU resources

Best Practices
--------------

1. **Use Appropriate Algorithms**: Choose FIPS-approved algorithms for your use case
2. **Implement Proper Error Handling**: Handle cryptographic exceptions gracefully
3. **Test Thoroughly**: Test in both FIPS and non-FIPS environments
4. **Document Requirements**: Document FIPS requirements for your features
5. **Monitor Performance**: Monitor performance impact of FIPS operations

Compliance Standards
--------------------

When developing FIPS-compliant features, ensure compliance with the following standards:

**FIPS 140-2** (Federal Information Processing Standards Publication 140-2)
    * Security requirements for cryptographic modules
    * Four security levels (1-4) based on module capabilities
    * Covers areas such as cryptographic module specification, ports/interfaces, roles/services, authentication, physical security, operational environment, cryptographic key management, EMI/EMC, self-tests, design assurance, and mitigation of attacks

**FIPS 140-3** (Federal Information Processing Standards Publication 140-3)
    * Updated version of FIPS 140-2, published in 2019
    * Maintains backward compatibility with FIPS 140-2
    * Enhanced requirements for modern cryptographic algorithms
    * Improved testing and validation processes

**Common Criteria** (ISO/IEC 15408)
    * International standard for computer security certification
    * Provides framework for evaluating security properties of IT products
    * Seven Evaluation Assurance Levels (EAL 1-7)
    * Commonly used for government and enterprise security evaluations

**NIST Guidelines**
    * SP 800-53: Security and Privacy Controls for Federal Information Systems
    * SP 800-131A: Transitions for Deprecated Cryptographic Algorithms
    * SP 800-57: Recommendation for Key Management
    * Provide specific guidance on implementing cryptographic modules

**Implementation Requirements**
    * Use only FIPS-approved cryptographic algorithms (AES, SHA-256, HMAC, PBKDF2; 3DES is disallowed for
      encryption since 2023 by SP 800-131A rev. 2)
    * Implement proper key management and storage
    * Ensure secure random number generation
    * Provide self-test capabilities
    * Maintain detailed security audit logs
    * Follow secure coding practices to prevent common vulnerabilities

For specific compliance requirements, consult your organization's security policies and the relevant standards documentation. GeoServer's FIPS implementation focuses on FIPS 140-3 Level 1 compliance for cryptographic operations. 