# FIPS 140-3

The FIPS module runs GeoServer against a FIPS 140-3 validated cryptography module, so every
cryptographic operation GeoServer performs happens inside a validated boundary. It replaces the
regular BouncyCastle library with the FIPS validated one, registers it ahead of the Java providers,
and sets it in approved-only mode. It also stores passwords with AES-GCM, which the validated module
supports.

Deployments that need this are the ones bound by a policy such as FIPS 140-3, usually United States
federal ones or their suppliers.

<div class="grid cards" markdown>

- [Installing the FIPS module](installing.md)
- [Running GeoServer under FIPS](running.md)

</div>

!!! warning
    A data directory written by a normal GeoServer stores its passwords and keys with algorithms that
    approved-only mode refuses. GeoServer moves them to the FIPS formats on the first start with the
    module installed, but two of the steps need algorithms a machine already in FIPS mode no longer
    offers, so that first start has to happen before the machine is put in FIPS mode. See
    [Moving an existing data directory](running.md#moving-an-existing-data-directory).

!!! warning
    The FIPS module works on Linux only.
