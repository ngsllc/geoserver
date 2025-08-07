.. _security_keystore_config:

Keystore Type Configuration Security
===================================

This document describes the security aspects of GeoServer's configurable keystore types.

Overview
--------

The keystore type configuration feature provides flexibility in choosing keystore formats while maintaining security standards appropriate for different deployment environments.

Security Features
----------------

Keystore Format Security
~~~~~~~~~~~~~~~~~~~~~~~

* **JCEKS**: Standard Java keystore with proven security
* **BCFKS**: Enhanced security for FIPS-compliant environments
* **PKCS12**: Industry-standard format with broad compatibility

Key Management
~~~~~~~~~~~~~

* **Secure key storage** in selected keystore format
* **Password protection** for keystore access
* **Key rotation support** through keystore replacement

Configuration Security
---------------------

Environment Variable Security
~~~~~~~~~~~~~~~~~~~~~~~~~~~

* **Runtime configuration** via environment variables
* **No hardcoded secrets** in configuration files
* **Deployment-specific settings** for different environments

File Security
~~~~~~~~~~~~

* **Automatic file naming** based on keystore type
* **Proper file permissions** should be set by administrator
* **Secure file location** in GeoServer data directory

Supported Keystore Types
-----------------------

JCEKS (Default)
~~~~~~~~~~~~~~~

**Security Level**: Standard
**Use Case**: General deployments
**Features**:
* Java standard keystore format
* Password-protected key storage
* Compatible with all Java environments

BCFKS
~~~~~

**Security Level**: Enhanced (with FIPS JVM)
**Use Case**: FIPS-compliant environments
**Features**:
* BouncyCastle FIPS keystore format
* Enhanced cryptographic algorithms
* FIPS 140-2 compliance (when used with FIPS JVM)

PKCS12
~~~~~~

**Security Level**: Standard
**Use Case**: Cross-platform deployments
**Features**:
* Industry-standard format
* Broad system compatibility
* Password-protected storage

Security Configuration
---------------------

Environment Setup
~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Secure environment variable setting
   export GEOSERVER_KEYSTORE_TYPE=BCFKS
   
   # Verify configuration
   echo $GEOSERVER_KEYSTORE_TYPE

File Permissions
~~~~~~~~~~~~~~~

.. code-block:: bash

   # Set secure permissions on keystore files
   chmod 600 geoserver.jceks
   chmod 600 geoserver.bcfks
   chmod 600 geoserver.p12
   
   # Set secure permissions on data directory
   chmod 700 $GEOSERVER_DATA_DIR

Docker Security
~~~~~~~~~~~~~~

.. code-block:: dockerfile

   # Secure Docker configuration
   ENV GEOSERVER_KEYSTORE_TYPE=BCFKS
   
   # Run as non-root user
   USER geoserver
   
   # Mount keystore with proper permissions
   VOLUME ["/opt/geoserver/data_dir/security"]

Security Best Practices
----------------------

Keystore Management
~~~~~~~~~~~~~~~~~~

* **Regular key rotation** for enhanced security
* **Secure backup** of keystore files
* **Access control** on keystore files
* **Monitoring** of keystore access

Environment Security
~~~~~~~~~~~~~~~~~~~

* **Secure environment variables** in production
* **No hardcoded secrets** in configuration
* **Principle of least privilege** for file access
* **Regular security audits** of configuration

Migration Security
~~~~~~~~~~~~~~~~~

* **Secure key export** during migration
* **Verification** of migrated keystores
* **Testing** in non-production environment
* **Rollback plan** for failed migrations

Security Considerations
----------------------

FIPS Compliance
~~~~~~~~~~~~~~

* **BCFKS format** supports FIPS compliance
* **JVM must be configured** for FIPS mode
* **No automatic FIPS validation** in GeoServer
* **Manual verification** required for compliance

Algorithm Security
~~~~~~~~~~~~~~~~~

* **Uses JVM default algorithms** for each keystore type
* **No algorithm enforcement** implemented
* **Relies on JVM security configuration**
* **Review JVM security settings** for compliance

Provider Security
~~~~~~~~~~~~~~~~

* **JVM handles provider selection** automatically
* **No manual provider registration** required
* **Fallback to default** if provider unavailable
* **Verify provider availability** in deployment

Limitations
-----------

Security Limitations
~~~~~~~~~~~~~~~~~~~

* **No automatic FIPS validation** - manual verification required
* **No algorithm enforcement** - relies on JVM configuration
* **No provider validation** - assumes providers available
* **No key strength validation** - uses JVM defaults

Compliance Considerations
~~~~~~~~~~~~~~~~~~~~~~~~

* **FIPS 140-2**: Requires FIPS-configured JVM with BCFKS
* **Common Criteria**: Depends on JVM certification
* **Industry Standards**: Varies by keystore type
* **Audit Requirements**: Manual verification needed

Monitoring and Auditing
----------------------

Security Monitoring
~~~~~~~~~~~~~~~~~~

* **Monitor keystore access** patterns
* **Log keystore operations** for audit
* **Alert on unusual access** patterns
* **Regular security reviews** of configuration

Audit Trail
~~~~~~~~~~~

* **Keystore creation** events
* **Key access** patterns
* **Configuration changes** tracking
* **Migration activities** logging

Incident Response
~~~~~~~~~~~~~~~~

* **Keystore compromise** procedures
* **Key rotation** processes
* **Backup restoration** procedures
* **Configuration recovery** plans

Future Security Enhancements
---------------------------

Planned Improvements
~~~~~~~~~~~~~~~~~~~

* **FIPS mode detection** and validation
* **Algorithm enforcement** for compliance
* **Provider validation** and error handling
* **Enhanced audit logging** for security events
* **Automated security checks** during startup
