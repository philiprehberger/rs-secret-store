# Changelog

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
