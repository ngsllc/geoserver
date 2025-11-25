.. _security_fips_dev:

FIPS Development
===============

This section provides information for developers working with FIPS-compliant features in GeoServer.

FIPS-aware keystore handling
---------------------------

GeoServer's ``KeyStoreProviderImpl`` detects FIPS mode via ``com.redhat.fips`` (defined as ``FIPS_PROPERTY_NAME`` constant) and, when unspecified,
defaults the keystore type to PKCS12. It also infers the keystore type from the filename extension and
falls back to legacy keystore files (``geoserver.jceks``, ``geoserver.jks``, ``geoserver.bcfks``) if the
configured file is not present. This enables safe migration without breaking existing deployments.

Key Features
~~~~~~~~~~~

* **Automatic FIPS Detection**: Detects FIPS mode through system properties
* **Filename Inference**: Infers keystore type from extension
* **Legacy Fallback**: Falls back to legacy keystore files when the configured one is missing
* **Provider Fallback**: Registers/uses BouncyCastle providers for BCFKS when necessary

Implementation Details
~~~~~~~~~~~~~~~~~~~~~

Building with FIPS Support
^^^^^^^^^^^^^^^^^^^^^^^^^^

GeoServer supports two build approaches for FIPS compatibility:

Universal Build (Recommended)
"""""""""""""""""""""""""""""

.. code-block:: bash

   # Build universal distribution (works on both FIPS and non-FIPS)
   mvn clean install -Puniversal

This creates a distribution that includes both BC-FIPS and regular BouncyCastle libraries. The runtime detection system ensures only the appropriate provider is loaded, avoiding package sealing conflicts.

**Technical Details:**
* BC-FIPS JARs are included as optional dependencies
* Regular BouncyCastle JARs are included normally
* ``KeyStoreProviderImpl.isFipsEnvironment()`` determines which provider to load
* ``GeoServerPBEPasswordEncoder.ensureProviderAvailableIfRequested()`` conditionally registers providers

FIPS-Only Build
"""""""""""""""

.. code-block:: bash

   # Build FIPS-only distribution
   mvn clean install -Pfips

This creates a FIPS-optimized distribution that excludes regular BouncyCastle providers entirely, preventing any possibility of conflicts.

Core Implementation
^^^^^^^^^^^^^^^^^^^

The core keystore provider implements the following key methods:

.. code-block:: java

   KeyStoreProviderImpl provider = new KeyStoreProviderImpl();
   provider.setSecurityManager(securityManager);
   provider.refreshKeyStoreType();

Configuration
~~~~~~~~~~~~

Configure via:

* **System Properties**: ``com.redhat.fips=true``
* **Keystore Type**: ``GEOSERVER_KEYSTORE_TYPE=PKCS12|BCFKS|JCEKS``
* **Provider**: ``GEOSERVER_KEYSTORE_PROVIDER=BCFIPS|BC``

Testing FIPS behavior
~~~~~~~~~~~~~~~~~~~~~

Unit tests cover default type selection and provider resolution. For manual checks, set
``-Dcom.redhat.fips=true`` and verify PKCS12 defaulting in logs.

Integration with Security Framework
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use ``GeoServerSecurityManager#getKeyStoreProvider()`` to access the active provider; keystore
type and provider are resolved internally based on configuration and environment.

Development Guidelines
--------------------

When developing FIPS-compliant features:

1. **Use FIPS-Approved Algorithms**: Always use FIPS-approved cryptographic algorithms
2. **Test in FIPS Mode**: Test your code in FIPS-enabled environments
3. **Handle Provider Failures**: Implement proper fallback mechanisms
4. **Log Security Events**: Log security-related events for audit purposes
5. **Validate Inputs**: Validate all cryptographic inputs

Example: Creating a FIPS-Compliant Service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: java

   KeyStoreProvider provider = securityManager.getKeyStoreProvider();
   String defaultType = KeyStoreProviderImpl.getKeyStoreType();

Keystore migration (JCEKS → PKCS12/BCFKS)
-----------------------------------------

To migrate an existing ``geoserver.jceks`` to PKCS12:

.. code-block:: bash

   MASTER='geoserver'
   keytool -importkeystore \
     -srckeystore /path/to/data/security/geoserver.jceks \
     -srcstoretype JCEKS \
     -srcstorepass "$MASTER" \
     -destkeystore /path/to/data/security/geoserver.pkcs12 \
     -deststoretype PKCS12 \
     -deststorepass "$MASTER" \
     -noprompt

For BCFKS instead:

.. code-block:: bash

   keytool -importkeystore \
     -srckeystore /path/to/data/security/geoserver.jceks -srcstoretype JCEKS -srcstorepass "$MASTER" \
     -destkeystore /path/to/data/security/geoserver.bcfks -deststoretype BCFKS -deststorepass "$MASTER" -noprompt

Debugging FIPS Issues
--------------------

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

      boolean fipsMode = System.getProperty(KeyStoreProviderImpl.FIPS_PROPERTY_NAME) != null;
      System.out.println("FIPS Mode: " + fipsMode);

4. **Test Keystore Operations**:

   .. code-block:: java

      try {
          KeyStore keystore = KeyStore.getInstance("PKCS12");
          keystore.load(null, "password".toCharArray());
          System.out.println("Keystore created successfully");
      } catch (Exception e) {
          System.err.println("Keystore creation failed: " + e.getMessage());
      }

Performance Considerations
------------------------

FIPS-compliant cryptographic operations may have performance implications:

* **Slower Operations**: FIPS-compliant algorithms may be slower than standard algorithms
* **Memory Usage**: FIPS providers may use more memory
* **CPU Usage**: Cryptographic operations may use more CPU resources

Best Practices
-------------

1. **Use Appropriate Algorithms**: Choose FIPS-approved algorithms for your use case
2. **Implement Proper Error Handling**: Handle cryptographic exceptions gracefully
3. **Test Thoroughly**: Test in both FIPS and non-FIPS environments
4. **Document Requirements**: Document FIPS requirements for your features
5. **Monitor Performance**: Monitor performance impact of FIPS operations

Compliance Standards
-------------------

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
    * Use only FIPS-approved cryptographic algorithms (AES, 3DES, SHA-256, etc.)
    * Implement proper key management and storage
    * Ensure secure random number generation
    * Provide self-test capabilities
    * Maintain detailed security audit logs
    * Follow secure coding practices to prevent common vulnerabilities

For specific compliance requirements, consult your organization's security policies and the relevant standards documentation. GeoServer's FIPS implementation focuses on FIPS 140-2 Level 1 compliance for cryptographic operations. 