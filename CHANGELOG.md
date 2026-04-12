# Changelog

## 0.3.0 (2026-04-11)

- Add `SecretStore::clear()` method to wipe all secrets at once
- Add missing `From<String>`, `From<&str>`, and `From<Vec<u8>>` trait implementations
- Add missing `SecretStore::contains_key()` method
- Add `#[must_use]` annotations on `SecretStore` query methods

## 0.2.4 (2026-03-31)

- Standardize README to 3-badge format with emoji Support section
- Update CI checkout action to v5 for Node.js 24 compatibility

## 0.2.3 (2026-03-27)

- Add GitHub issue templates, PR template, and dependabot configuration
- Update README badges and add Support section

## 0.2.2 (2026-03-22)

- Remove extra serde install snippet from Installation section

## 0.2.1 (2026-03-22)

- Fix README and CI compliance

## 0.2.0 (2026-03-20)

- Add From<String>, From<Vec<u8>>, and From<&str> implementations for Secret
- Add Secret::clear() for manual zeroization without dropping
- Add SecretStore::contains_key() method
- Add #[must_use] attributes on query and accessor methods

## 0.1.0 (2026-03-19)

- `Secret<T>` wrapper with automatic zeroization on drop
- TTL-based expiry with `with_ttl` constructor
- `expose` and `expose_or` for controlled access to secret values
- `needs_rotation` helper for age-based rotation policies
- `SecretString` type alias with `from_env` and `from_env_required`
- `SecretBytes` type alias for binary secrets
- `SecretStore` keyed collection with expiry management
- Redacted `Debug` and `Display` implementations (never reveal values)
- Optional `serde` feature: deserialize secrets normally, serialize as `"****"`
- `SecretError` enum for error handling
