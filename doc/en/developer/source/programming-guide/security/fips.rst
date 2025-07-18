.. _security_fips_dev:

FIPS Development
===============

This section provides information for developers working with FIPS-compliant features in GeoServer.

FIPS KeyStore Provider
---------------------

The ``FIPSKeyStoreProvider`` class extends ``KeyStoreProviderImpl`` to provide FIPS compliance. It automatically detects FIPS mode and configures appropriate cryptographic providers.

Key Features
~~~~~~~~~~~

* **Automatic FIPS Detection**: Detects FIPS mode through system properties and environment variables
* **Provider Fallback**: Falls back to standard providers when FIPS providers are not available
* **Keystore Type Configuration**: Configures appropriate keystore types for FIPS environments
* **Integration**: Seamlessly integrates with GeoServer's security framework

Implementation Details
~~~~~~~~~~~~~~~~~~~~~

The FIPS keystore provider implements the following key methods:

.. code-block:: java

   public class FIPSKeyStoreProvider extends KeyStoreProviderImpl {
       
       private boolean fipsMode = false;
       private Provider cryptoProvider;
       
       public FIPSKeyStoreProvider() {
           super();
           initializeFIPSProvider();
       }
       
       private void initializeFIPSProvider() {
           // Check FIPS mode
           String fipsMode = System.getProperty("com.redhat.fips");
           if (fipsMode != null && fipsMode.equals("true")) {
               this.fipsMode = true;
           }
           
           // Try to load FIPS provider
           try {
               Class<?> fipsProviderClass = Class.forName(FIPS_PROVIDER_CLASS);
               cryptoProvider = (Provider) fipsProviderClass.getDeclaredConstructor().newInstance();
               Security.addProvider(cryptoProvider);
               this.fipsMode = true;
           } catch (Exception e) {
               // Fall back to standard provider
               try {
                   Class<?> standardProviderClass = Class.forName(STANDARD_PROVIDER_CLASS);
                   cryptoProvider = (Provider) standardProviderClass.getDeclaredConstructor().newInstance();
                   Security.addProvider(cryptoProvider);
               } catch (Exception ex) {
                   // No BouncyCastle provider available
               }
           }
       }
   }

Configuration
~~~~~~~~~~~~

The FIPS keystore provider can be configured through:

* **System Properties**: ``com.redhat.fips=true``
* **Environment Variables**: ``FIPS_MODE=true``
* **Keystore Type**: ``GEOSERVER_KEYSTORE_TYPE=PKCS12``
* **Provider**: ``GEOSERVER_KEYSTORE_PROVIDER=BCFIPS``

Testing FIPS Compliance
~~~~~~~~~~~~~~~~~~~~~~~

To test FIPS compliance in your development environment:

.. code-block:: java

   @Test
   public void testFIPSCompliance() {
       FIPSKeyStoreProvider provider = new FIPSKeyStoreProvider();
       
       // Test FIPS mode detection
       assertTrue(provider.isFIPSMode());
       
       // Test provider availability
       assertNotNull(provider.getCryptoProvider());
       
       // Test keystore type
       assertEquals("PKCS12", provider.getDefaultKeyStoreType());
   }

Integration with Security Framework
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The FIPS keystore provider integrates with GeoServer's security framework:

.. code-block:: java

   // Get the security manager
   GeoServerSecurityManager securityManager = GeoServerExtensions.bean(GeoServerSecurityManager.class);
   
   // Get the keystore provider
   KeyStoreProvider keystoreProvider = securityManager.getKeyStoreProvider();
   
   // Check if it's FIPS-compliant
   if (keystoreProvider instanceof FIPSKeyStoreProvider) {
       FIPSKeyStoreProvider fipsProvider = (FIPSKeyStoreProvider) keystoreProvider;
       if (fipsProvider.isFIPSMode()) {
           // FIPS mode is active
           LOGGER.info("FIPS mode is active");
       }
   }

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

   public class FIPSCompliantService {
       
       private final FIPSKeyStoreProvider keystoreProvider;
       
       public FIPSCompliantService(FIPSKeyStoreProvider keystoreProvider) {
           this.keystoreProvider = keystoreProvider;
       }
       
       public byte[] encryptData(byte[] data, String password) throws Exception {
           if (!keystoreProvider.isFIPSMode()) {
               throw new SecurityException("FIPS mode is required");
           }
           
           // Use FIPS-approved encryption
           Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", keystoreProvider.getCryptoProvider());
           // ... encryption logic
       }
   }

Migration Utilities
-----------------

For migrating existing keystores to FIPS-compliant formats, standalone utilities are available in the NGS GeoServer project:

* **MigrateKeystore**: Utility for migrating keystores between formats
* **FIPSKeyStoreProvider**: Standalone utility for testing FIPS compliance

These utilities are located in:
``ngs-geoserver/java/geoserver-addons/src/main/java/com/ngs/geoserver/security/``

Debugging FIPS Issues
--------------------

Common debugging techniques for FIPS-related issues:

1. **Enable Debug Logging**:

   .. code-block:: properties

      org.geoserver.security.FIPSKeyStoreProvider=DEBUG

2. **Check Provider Availability**:

   .. code-block:: java

      Provider[] providers = Security.getProviders();
      for (Provider p : providers) {
          System.out.println(p.getName() + " - " + p.getVersion());
      }

3. **Verify FIPS Mode**:

   .. code-block:: java

      boolean fipsMode = System.getProperty("com.redhat.fips") != null;
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

When developing FIPS-compliant features, ensure compliance with:

* **FIPS 140-2**: Federal Information Processing Standards
* **FIPS 140-3**: Updated FIPS standards (when available)
* **Common Criteria**: International security standards
* **NIST Guidelines**: National Institute of Standards and Technology recommendations

For specific compliance requirements, consult your organization's security policies and the relevant standards documentation. 