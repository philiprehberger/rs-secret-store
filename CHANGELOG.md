# Changelog

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
