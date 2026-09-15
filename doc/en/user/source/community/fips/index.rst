.. _community_fips:

FIPS 140-3 support
==================

The FIPS module runs GeoServer against a FIPS 140-3 validated cryptography module, so every
cryptographic operation GeoServer performs happens inside a validated boundary. It replaces the
regular BouncyCastle library with the FIPS validated one, registers it ahead of the Java providers,
and sets it in approved-only mode. It also stores passwords with AES-GCM, which the validated module
supports.

Deployments that need this are the ones bound by a policy such as FIPS 140-3, usually United States
federal ones or their suppliers.

.. warning::

   A data directory written by a normal GeoServer stores its passwords and keys with algorithms that
   approved-only mode refuses. GeoServer moves them to the FIPS formats on the first start with the
   module installed, but two of the steps need algorithms a machine already in FIPS mode no longer
   offers, so that first start has to happen before the machine is put in FIPS mode. See
   `Moving an existing data directory`_.

.. warning::

   The FIPS module works on Linux only.

Installing the FIPS module
---------------------------

Installing this extension works like any other, with one addition: you also have to remove the
regular BouncyCastle jars that GeoServer ships. Do that in the war file, before you deploy it. A
stock GeoServer does not start on a machine that is already in FIPS mode.

Installing
~~~~~~~~~~

#. Check the version you are going to install. A running GeoServer shows it in
   **About & Status > About GeoServer**, under **Build Information**.

#. Open the `website download <https://geoserver.org/download>`__ page, go to the **Development**
   tab and find the nightly build matching your version. Follow the **Community Modules** link and
   download the ``fips`` archive.

#. Stop GeoServer.

#. A war file is a zip file. Unpack it, replace the three regular BouncyCastle jars in
   ``WEB-INF/lib`` with the ones from the plugin archive, delete the data directory bundled in the
   war (a deployment points at its own anyway), then pack it again:

   .. code-block:: bash

      unzip -q geoserver.war -d geoserver
      rm geoserver/WEB-INF/lib/bcprov-jdk18on-*.jar \
         geoserver/WEB-INF/lib/bcpkix-jdk18on-*.jar \
         geoserver/WEB-INF/lib/bcutil-jdk18on-*.jar
      unzip -q -o geoserver-<version>-fips-plugin.zip -d geoserver/WEB-INF/lib
      ls geoserver/WEB-INF/lib | grep -i '^bc'     # only the fips jars, nothing else
      rm -rf geoserver/data                        # the bundled sample data directory
      (cd geoserver && zip -q -r ../geoserver-fips.war .)

#. Deploy ``geoserver-fips.war`` under the name the old one had.

#. Point GeoServer at its data directory and start it again. An existing directory is moved to the
   FIPS formats on this start, which has to happen while the machine is not yet in FIPS mode; a new
   one is created in them. See `Running GeoServer under FIPS`_ for both.

#. Log in and open **About & Status > Server Status**, tab **FIPS**. The tab exists only when the
   module is installed. Read it before configuring anything else, see `Reading the FIPS tab`_.

The operating system and the Java runtime
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The module only changes GeoServer. It does not put the machine in FIPS mode: that is a boot time
setting of the kernel, and it covers TLS, OpenSSL and everything outside the Java runtime. Turn it
on with the tools of your distribution, for example on Red Hat family systems:

.. code-block:: bash

   sudo fips-mode-setup --enable
   sudo reboot
   cat /proc/sys/crypto/fips_enabled     # 1 when it is on

Use the Java runtime your distribution ships, not one you download yourself. On a Red Hat family
system only the packaged runtime reads the system cryptographic policy and applies it to Java.

Approved-only mode
~~~~~~~~~~~~~~~~~~~

The module turns on approved-only mode. A request for a non-approved algorithm then fails instead
of running quietly. Leave it off and the deployment is not FIPS compliant, because the validated
module still serves MD5 and DES.

The provider reads the setting once, while its class loads, and the module sets it just before
loading that class. If something else in the same JVM loaded a BouncyCastle class first, another
web application in the container for instance, or a monitoring agent, the setting comes too late and
the provider runs without it. GeoServer checks for that and refuses to start rather than run
non-approved algorithms while reporting that it does not; the message names the fix, which is to
give the JVM the setting from the start:

.. code-block:: text

   -Dorg.bouncycastle.fips.approved_only=true

Do that anyway on a container that hosts more than GeoServer.

A system property turns it off, and the FIPS tab then reports that:

.. code-block:: text

   -Dorg.bouncycastle.fips.approved_only=false

Only do that to diagnose a startup failure. A deployment bound by a FIPS policy runs with it on.

Running GeoServer under FIPS
------------------------------

Moving an existing data directory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A data directory written by a normal GeoServer uses algorithms that approved-only mode refuses,
in three places:

- The keystore holding the configuration keys is a JCEKS file, whose password protection is MD5
  and DES.
- The master password is stored in a file protected with MD5 and DES.
- Stored passwords name the encryption that wrote them: ``crypt1`` (MD5 and DES) for the oldest
  installations, ``crypt2`` (a PKCS#12 scheme of the regular BouncyCastle provider) for everything
  after. Both are used for user and group passwords and for store connection passwords.

GeoServer moves all of it on the first start with the FIPS module installed, and logs each step at
``WARNING``:

.. list-table::
   :header-rows: 1
   :widths: 25 25 25 25

   * - what
     - before
     - after
     - the old file
   * - keystore
     - ``security/geoserver.jceks``
     - ``security/geoserver.bcfks``, same keys
     - kept as ``geoserver.jceks.backup``
   * - master password
     - ``security/masterpw/default/passwd``, MD5 and DES
     - same file, AES-GCM; the provider configuration names ``AesGcmMasterPasswordProvider``
     - kept as ``passwd.backup``
   * - configuration password encoder
     - ``crypt1`` or ``crypt2``
     - ``crypt3``, every store password written again
     - none, the configuration files are rewritten in place
   * - user group services on ``crypt1`` or ``crypt2``
     -
     - switched to ``crypt3``, every password written again
     - none

Two of these steps read the old formats through the Java runtime rather than through the FIPS
provider: JCEKS and MD5/DES come from the JDK providers, which stay registered behind the FIPS one.
On a machine already in FIPS mode the system cryptographic policy has removed them from Java, and
GeoServer stops at the first of them — the master password — with a message naming the file, the
constraint and this page. **Do the move before turning FIPS mode on for the machine**, or on another
machine: install the FIPS module, start GeoServer once on the existing data directory, check the log
and the **FIPS** tab, then put the machine in FIPS mode and start it again. The ``crypt2`` step does
not have this constraint: ``crypt2`` values are read with the approved building blocks of that
scheme, SHA-256 and AES, without asking any provider for the cipher that wrote them.

Things the move cannot do, each reported at ``SEVERE`` in the log:

- A user group service that cannot be written, such as one backed by a read-only file or a
  directory, keeps its ``crypt1`` or ``crypt2`` passwords. Its ``crypt2`` users go on logging in
  normally, since those values stay readable; its ``crypt1`` users cannot log in until the passwords
  are set again by whatever manages that service.
- ``crypt1`` values on a machine whose Java runtime no longer offers MD5/DES cannot be read, so they
  cannot be written again either. The encoders are switched all the same; the passwords have to be
  entered again.
- The master password is left as it is when it is stored by a read-only provider, or anywhere other
  than a file — there is nowhere to keep a copy of the old form, so it is not rewritten. GeoServer
  runs, because the old form is still readable on this machine, but it will not be once the machine
  is in FIPS mode. Store the password again from **Security > Passwords**, through a writable
  file-backed provider, before then.
- A user password that cannot be read — damaged, hand edited, or encrypted under another
  installation's key — is left as it is and named in the log. That user cannot log in; set their
  password again. The rest of the service is migrated normally.

**Copy the data directory before the first FIPS start.** The move rewrites the keystore, the master
password and every stored password in place, and there is no dry run: the only way to try it is to
try it. A copy is also the quickest way back if something about the result is not what you expected.

Keep the ``.backup`` files afterwards until the deployment has run for a while. Together with the
old ``config.xml`` files, which the version control of your choice should hold anyway, they take the
directory back to the normal GeoServer it came from.

If a start fails part way through the move, look at what the log reached before the error. Each step
either completes or leaves the directory as it was, and a step that completed is skipped on the next
start, so fixing what the message names and starting again continues from there. The one case that
needs a hand is a master password file that was rewritten while its configuration was not, or the
reverse, which leaves GeoServer unable to read its own master password: restore
``security/masterpw/default/passwd`` from the ``.backup`` beside it and start again.

Starting from a new data directory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A directory GeoServer creates under FIPS differs from a normal one in three places. All three are
visible in the **FIPS** tab of **About & Status > Server Status**:

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - what
     - normal GeoServer
     - under FIPS
   * - keystore holding the configuration keys
     - JCEKS
     - BCFKS, BouncyCastle's own format
   * - encryption of stored passwords
     - ``crypt1`` and ``crypt2``
     - ``crypt3``, AES-GCM with a key derived by PBKDF2
   * - storage of the master password
     - password based encryption in a file
     - AES-GCM in a file

Create that directory before you start: GeoServer ignores a ``GEOSERVER_DATA_DIR`` that does not
exist and builds one inside the web application instead.

.. note::

   The keystore file is named after its format. A normal install keeps ``security/geoserver.jceks``,
   a FIPS one gets ``security/geoserver.bcfks``. GeoServer checks the first bytes of the file against
   the format it expects and refuses to start when they disagree, rather than creating an empty
   keystore and losing the keys your passwords were encrypted with.

The ``crypt3`` encryption is not FIPS specific. It uses algorithms every Java runtime offers, so a
normal GeoServer with the same keystore reads a value written under FIPS.

As on any new data directory, the administrator account is the standard one, ``admin`` with password
``geoserver``. Change it on first login, from **Security > Users, Groups, Roles**.

Reading the FIPS tab
~~~~~~~~~~~~~~~~~~~~~

The tab has two tables. The first one reports the cryptography in force, with short values:

.. list-table::
   :header-rows: 1
   :widths: 25 20 55

   * - Item
     - Value in a FIPS deployment
     - Meaning
   * - Crypto module
     - ``READY``
     - The validated module passed its own self tests when GeoServer started. Any other value means
       the deployment is not FIPS compliant, whatever the rest of the page says.
   * - Approved-only mode
     - ``on``
     - A request for a non-approved algorithm fails. ``off`` means it was turned off with a system
       property and non-approved algorithms are allowed to run. ``requested, but NOT in force`` means
       it was asked for but the provider was initialized by something else before the request could
       reach it; GeoServer refuses to start in that state, see `Approved-only mode`_, so a running
       instance never shows it.
   * - Operating system FIPS mode
     - ``yes``
     - The kernel FIPS flag. ``no`` means the machine is not in FIPS mode, ``unknown`` that it does
       not say. The module cannot set it, see `Installing the FIPS module`_.
   * - Crypto provider
     - ``BCFIPS`` and its version
     - The validated module registered with Java. ``not installed`` means GeoServer is not using it.
   * - Provider position
     - ``first``
     - Java uses the first provider that offers an algorithm. ``behind <name>`` means another
       provider answers first and does the work outside the validated module.
   * - Keystore format
     - ``BCFKS``
     - Format of the keystore holding the configuration keys. Anything else means the data directory
       was created without FIPS.
   * - Config password encoder
     - ``AES-GCM``
     - How passwords in the catalog are encrypted, such as store connection parameters.
   * - User password encoder
     - ``AES-GCM``
     - How passwords held by user group services are encrypted.
   * - Master password storage
     - ``AES-GCM file``
     - How the master password is kept.
   * - Random source
     - generator and provider
     - The generator GeoServer draws salts, initialization vectors and keys from, with the provider
       in round brackets. GeoServer asks the FIPS provider for it by name, so a provider other than
       ``BCFIPS`` means the provider is not installed.

The keystore, encoder and master password values are what this data directory currently uses. On a
directory created without FIPS they are what the move set, see `Moving an existing data directory`_;
they are not settings to change by hand on a running installation.

The second table lists the four algorithms GeoServer cannot work without, with a yes or no each: the
keystore format, ``AES/GCM/NoPadding``, ``PBKDF2WithHmacSHA256`` and ``SHA-256``. A ``no`` on any of
them means the security subsystem will fail somewhere, and this table says which piece is missing.

Reading the same values over REST
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The FIPS module reports itself among the module statuses, so the same values can be read without the
user interface. Ask for the HTML form of the module status list:

.. code-block:: bash

   curl -u admin:geoserver "http://localhost:8080/geoserver/rest/about/status.html"

The entry to look for is the one whose **Module** is ``gs-fips-provider``. Its **Message** holds one
line per item of the first table, then one line per required algorithm:

.. code-block:: text

   Crypto module: READY
   Approved-only mode: on
   Operating system FIPS mode: yes
   Crypto provider: BCFIPS 2.0102
   Provider position: first
   Keystore format: BCFKS
   Config password encoder: AES-GCM
   User password encoder: AES-GCM
   Master password storage: AES-GCM file
   Random source: DEFAULT (BCFIPS)
   KeyStore BCFKS: yes
   Cipher AES/GCM/NoPadding: yes
   SecretKeyFactory PBKDF2WithHmacSHA256: yes
   MessageDigest SHA-256: yes

The same entry has two boolean fields: **Available** is true when the module self tests passed,
**Enabled** when approved-only mode is in force for the thread answering the request.

.. note::

   The ``json`` and ``xml`` forms of ``rest/about/status`` list module names and links only, with no
   message, so none of the values above can be read there.

Limitations
~~~~~~~~~~~

**HTTP Digest authentication cannot be used.** MD5 is in the protocol itself, both ends have to
compute the same value, and the stored password format is MD5 too. Move those configurations to
another authentication method.

**Database passwords need at least 14 characters.** PostgreSQL authenticates with SCRAM, which
derives a key from the password, and approved-only mode refuses a derivation from a password shorter
than 112 bits. A shorter one makes the store fail to connect with ``password must be at least 112
bits`` in the log. The same holds for any other database that derives a key from the password rather
than sending it. Command line tools such as ``psql`` do not use Java cryptography, so the same
account can work fine outside GeoServer.

**A library may ask for a random source that a FIPS system does not have.** Nothing in GeoServer
does, but a third party extension calling ``SecureRandom.getInstanceStrong()`` fails on a Red Hat
family FIPS system: both generators named as strong there belong to a provider the policy has
emptied. Only a change to the Java security configuration fixes that.

Log messages that are not problems
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- ``The default SHA1PRNG algorithm for SecureRandom is not supported by this JVM. Using the platform
  default.``, from Tomcat at startup. The platform default on a FIPS machine is a FIPS generator, so
  the session identifiers are compliant.
- ``SecureRandom algorithm 'DRBG' is not available``, at ``FINE`` level. ``DRBG`` is a stock Java
  name owned by a provider that a FIPS system empties, not a forbidden algorithm. The validated
  module's own generator takes over.
