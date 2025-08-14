.. _security_cache:

Authentication cache keys
=========================

GeoServer uses short-lived, in-memory caches in some security filters to avoid
recomputing authentication for identical requests. These cache entries are keyed
using a digest of non-sensitive values (for example, a hash of ``password:filterName``),
stored only in memory and never logged.

Algorithm used for cache digests
--------------------------------

Starting with this branch, internal cache digests use **SHA-256** instead of MD5.

- This change improves alignment with FIPS recommendations.
- It does not affect any wire protocol or interoperability.
- It does not change user-facing configuration or persisted data.

Note that HTTP Digest authentication still uses the algorithm defined by the
relevant RFC (commonly MD5) for protocol compatibility; this is separate from
the internal cache digests described above.


