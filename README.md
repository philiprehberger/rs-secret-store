# rs-secret-store

[![CI](https://github.com/philiprehberger/rs-secret-store/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rs-secret-store/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/philiprehberger-secret-store.svg)](https://crates.io/crates/philiprehberger-secret-store)
[![License](https://img.shields.io/github/license/philiprehberger/rs-secret-store)](LICENSE)

Secure in-memory secret storage with automatic zeroization, expiry, and redacted display

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
philiprehberger-secret-store = "0.1.0"
```

For serde support (deserialize secrets, serialize as redacted):

```toml
[dependencies]
philiprehberger-secret-store = { version = "0.1.0", features = ["serde"] }
```

## Usage

### Secret wrapper

```rust
use philiprehberger_secret_store::Secret;
use std::time::Duration;

// Wrap a secret value — automatically zeroized on drop
let api_key = Secret::new("sk-abc123".to_string());

// Access the value through a closure
api_key.expose(|key| {
    println!("Key: {key}");
});

// Debug and Display never reveal the value
println!("{:?}", api_key); // Secret(****)
println!("{}", api_key);   // ****

// TTL-based expiry
let token = Secret::with_ttl("temp-token".to_string(), Duration::from_secs(3600));
assert!(!token.is_expired());

// Safe access that returns None if expired
let result = token.expose_or(|t| t.clone());

// Rotation check
if token.needs_rotation(Duration::from_secs(86400)) {
    // Token is older than 24 hours
}
```

### SecretString from environment

```rust
use philiprehberger_secret_store::SecretString;

// Load from env var and immediately remove it from the environment
if let Some(secret) = SecretString::from_env("API_KEY") {
    secret.expose(|key| {
        // use key
    });
}

// Or require the env var
let secret = SecretString::from_env_required("DATABASE_URL").expect("DATABASE_URL must be set");
```

### SecretStore

```rust
use philiprehberger_secret_store::SecretStore;
use std::time::Duration;

let mut store = SecretStore::new();

// Insert secrets
store.insert("api_key", "sk-abc123");
store.insert_with_ttl("session_token", "tok-xyz", Duration::from_secs(3600));

// Retrieve and expose
if let Some(key) = store.expose("api_key") {
    println!("Key: {key}");
}

// Debug shows keys but never values
println!("{:?}", store); // SecretStore { api_key: ****, session_token: **** }

// Clean up expired secrets
store.remove_expired();
```

## API

### `Secret<T>`

| Method | Description |
|---|---|
| `Secret::new(value)` | Wrap a value as a secret |
| `Secret::with_ttl(value, ttl)` | Wrap with a time-to-live |
| `.expose(f)` | Access value via closure (panics if expired) |
| `.expose_or(f)` | Access value via closure (returns `None` if expired) |
| `.is_expired()` | Check if the secret has expired |
| `.age()` | Duration since creation |
| `.needs_rotation(max_age)` | True if age exceeds `max_age` |

### `SecretString`

| Method | Description |
|---|---|
| `SecretString::from_env(key)` | Load from env var, remove var |
| `SecretString::from_env_required(key)` | Load from env var or return error |

### `SecretStore`

| Method | Description |
|---|---|
| `SecretStore::new()` | Create an empty store |
| `.insert(key, value)` | Add a secret |
| `.insert_with_ttl(key, value, ttl)` | Add a secret with TTL |
| `.get(key)` | Get a reference to a `SecretString` |
| `.expose(key)` | Get + expose + clone the string |
| `.remove(key)` | Remove and zeroize a secret |
| `.remove_expired()` | Remove all expired secrets |
| `.keys()` | Iterate over key names |
| `.len()` | Number of secrets |
| `.is_empty()` | True if store is empty |

### `SecretError`

| Variant | Description |
|---|---|
| `Expired` | Secret has expired |
| `EnvVarNotFound(String)` | Environment variable not found |

## Development

```bash
cargo test
cargo clippy -- -D warnings
```

## License

MIT
