.. _production_keystore_config:

Keystore Type Configuration
===========================

GeoServer supports configurable keystore types through environment variables, allowing deployment flexibility and support for different keystore formats.

Overview
--------

The keystore type configuration feature allows GeoServer to use different keystore formats based on deployment requirements. This provides flexibility for different security environments and integration with existing infrastructure.

Supported Keystore Types
-----------------------

* **JCEKS** (default): Java Cryptography Extension KeyStore
* **BCFKS**: BouncyCastle FIPS KeyStore (requires BouncyCastle FIPS provider)
* **PKCS12**: PKCS#12 keystore format

Configuration
-------------

Keystore type is configured via environment variable:

.. code-block:: bash

   export GEOSERVER_KEYSTORE_TYPE=BCFKS

Available Options
~~~~~~~~~~~~~~~~

* ``JCEKS`` - Default Java keystore format
* ``BCFKS`` - BouncyCastle FIPS keystore format
* ``PKCS12`` - PKCS#12 keystore format

File Naming
-----------

Keystore files are automatically named based on the selected type:

* **JCEKS**: `geoserver.jceks`
* **BCFKS**: `geoserver.bcfks`
* **PKCS12**: `geoserver.p12`

Usage Examples
-------------

Default Configuration (JCEKS)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Uses default JCEKS format
   java -jar geoserver.war

BCFKS Configuration
~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Configure for BCFKS keystore
   export GEOSERVER_KEYSTORE_TYPE=BCFKS
   java -jar geoserver.war

PKCS12 Configuration
~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Configure for PKCS12 keystore
   export GEOSERVER_KEYSTORE_TYPE=PKCS12
   java -jar geoserver.war

Docker Configuration
-------------------

For Docker deployments, set the environment variable:

.. code-block:: dockerfile

   ENV GEOSERVER_KEYSTORE_TYPE=BCFKS

Or via docker-compose:

.. code-block:: yaml

   services:
     geoserver:
       image: geoserver:2.27.2
       environment:
         - GEOSERVER_KEYSTORE_TYPE=BCFKS

Backward Compatibility
---------------------

* **Existing JCEKS keystores** continue to work without changes
* **Automatic migration** not provided - manual keystore conversion required
* **Default behavior** unchanged for existing deployments

Security Considerations
----------------------

* **BCFKS** provides enhanced security when used with FIPS-compliant JVM
* **PKCS12** offers broad compatibility with other systems
* **JCEKS** remains the most widely supported format

Limitations
-----------

* **No automatic FIPS validation** - relies on JVM configuration
* **No algorithm enforcement** - uses JVM default algorithms
* **No provider validation** - assumes appropriate providers are available

Migration Guide
--------------

To migrate from JCEKS to another format:

1. **Export existing keys** from current keystore
2. **Set environment variable** for new format
3. **Import keys** into new keystore format
4. **Verify functionality** with new keystore

Example migration script:

.. code-block:: bash

   # Export from JCEKS
   keytool -importkeystore -srckeystore geoserver.jceks -destkeystore temp.p12 -srcstoretype JCEKS -deststoretype PKCS12
   
   # Set new format
   export GEOSERVER_KEYSTORE_TYPE=PKCS12
   
   # Start GeoServer with new keystore
   java -jar geoserver.war
