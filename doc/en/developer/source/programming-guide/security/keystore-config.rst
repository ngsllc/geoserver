.. _developer_keystore_config:

Keystore Type Configuration Implementation
==========================================

This document describes the implementation of configurable keystore types in GeoServer's security module.

Overview
--------

The keystore type configuration feature allows GeoServer to dynamically select keystore formats based on environment variables, providing deployment flexibility while maintaining backward compatibility.

Architecture
-----------

KeyStoreProviderImpl
~~~~~~~~~~~~~~~~~~~

The main keystore provider has been enhanced to support multiple keystore types:

* **Environment-based Configuration**: Keystore type is determined by `GEOSERVER_KEYSTORE_TYPE` environment variable
* **Dynamic File Naming**: Keystore files are named based on the selected type
* **Provider Selection**: JVM automatically selects appropriate cryptographic provider

Implementation Details
---------------------

Environment Variable Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: java

   public static String getKeyStoreType() {
       String keystoreType = System.getenv("GEOSERVER_KEYSTORE_TYPE");
       return keystoreType != null ? keystoreType : "JCEKS";
   }

Dynamic File Naming
~~~~~~~~~~~~~~~~~~

.. code-block:: java

   private String getKeyStoreFileName() {
       String keystoreType = getKeyStoreType();
       switch (keystoreType) {
           case "BCFKS":
               return "geoserver.bcfks";
           case "PKCS12":
               return "geoserver.p12";
           default:
               return "geoserver.jceks";
       }
   }

Keystore Creation
~~~~~~~~~~~~~~~~

.. code-block:: java

   KeyStore ks = KeyStore.getInstance(getKeyStoreType());
   ks.load(null, null);

Supported Keystore Types
-----------------------

JCEKS (Default)
~~~~~~~~~~~~~~~

* **Format**: Java Cryptography Extension KeyStore
* **Provider**: Default JVM provider
* **File Extension**: `.jceks`
* **Use Case**: Standard Java applications

BCFKS
~~~~~

* **Format**: BouncyCastle FIPS KeyStore
* **Provider**: BouncyCastle FIPS provider (if available)
* **File Extension**: `.bcfks`
* **Use Case**: FIPS-compliant environments

PKCS12
~~~~~~

* **Format**: PKCS#12 keystore format
* **Provider**: Default JVM provider
* **File Extension**: `.p12`
* **Use Case**: Cross-platform compatibility

Configuration Options
--------------------

Environment Variables
~~~~~~~~~~~~~~~~~~~~

* `GEOSERVER_KEYSTORE_TYPE`: Specifies keystore type (JCEKS, BCFKS, PKCS12)

Default Behavior
~~~~~~~~~~~~~~~

* **No environment variable**: Uses JCEKS
* **Invalid value**: Falls back to JCEKS
* **File naming**: Automatic based on type

Testing
-------

KeyStoreProviderImplTest
~~~~~~~~~~~~~~~~~~~~~~~

The test class verifies:

* **Default keystore type** is JCEKS
* **Environment variable override** works correctly
* **Provider creation** succeeds with different types
* **File naming** is correct for each type

Example Test
~~~~~~~~~~~

.. code-block:: java

   @Test
   public void testEnvironmentVariableOverride() {
       // Set environment variable
       System.setProperty("GEOSERVER_KEYSTORE_TYPE", "BCFKS");
       
       // Verify override
       assertEquals("BCFKS", KeyStoreProviderImpl.getKeyStoreType());
       
       // Restore default
       System.clearProperty("GEOSERVER_KEYSTORE_TYPE");
   }

Integration Points
-----------------

Spring Configuration
~~~~~~~~~~~~~~~~~~~

The keystore provider is configured in Spring context:

.. code-block:: xml

   <bean id="keyStoreProvider" 
         class="org.geoserver.security.KeyStoreProviderImpl">
   </bean>

Password Encoders
~~~~~~~~~~~~~~~~

Password encoders work with all keystore types:

* **AbstractGeoserverPasswordEncoder**: Enhanced error handling
* **GeoServerPBEPasswordEncoder**: Null provider support

Backward Compatibility
---------------------

* **Existing deployments**: No changes required
* **JCEKS keystores**: Continue to work unchanged
* **Configuration**: Optional environment variable

Migration Considerations
-----------------------

Manual Migration Required
~~~~~~~~~~~~~~~~~~~~~~~~

* **No automatic conversion** between keystore types
* **Manual key export/import** required
* **Testing recommended** after migration

Example Migration
~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Export from JCEKS
   keytool -importkeystore \
     -srckeystore geoserver.jceks \
     -destkeystore geoserver.p12 \
     -srcstoretype JCEKS \
     -deststoretype PKCS12

Security Considerations
----------------------

Provider Selection
~~~~~~~~~~~~~~~~~

* **JVM handles provider selection** automatically
* **No manual provider registration** required
* **Fallback to default** if provider unavailable

Algorithm Support
~~~~~~~~~~~~~~~~

* **Uses JVM default algorithms** for each keystore type
* **No algorithm enforcement** implemented
* **Relies on JVM security configuration**

Limitations
-----------

* **No FIPS validation**: Relies on JVM configuration
* **No algorithm enforcement**: Uses JVM defaults
* **No provider validation**: Assumes providers available

Future Enhancements
-------------------

Potential improvements:

* **FIPS mode detection** and validation
* **Algorithm enforcement** for security compliance
* **Provider validation** and error handling
* **Automatic migration** tools
