//! Secure in-memory secret storage with automatic zeroization, expiry, and redacted display.
//!
//! This crate provides a [`Secret`] wrapper that ensures sensitive values are:
//! - Zeroized from memory when dropped
//! - Never accidentally printed via `Debug` or `Display`
//! - Optionally expired after a configurable TTL
//!
//! A [`SecretStore`] is also provided for managing multiple named secrets with
//! expiry support.
//!
//! # Examples
//!
//! ```
//! use philiprehberger_secret_store::Secret;
//!
//! let api_key = Secret::new("my-secret-key".to_string());
//!
//! // Access the value through a closure
//! let len = api_key.expose(|key| key.len());
//! assert_eq!(len, 13);
//!
//! // Debug never reveals the value
//! assert_eq!(format!("{:?}", api_key), "Secret(****)");
//! ```

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// A wrapper that holds a sensitive value with automatic zeroization on drop.
///
/// The inner value is never exposed through `Debug` or `Display`. Access is
/// only possible through the [`expose`](Secret::expose) or
/// [`expose_or`](Secret::expose_or) methods.
pub struct Secret<T: Zeroize> {
    inner: T,
    created_at: Instant,
    ttl: Option<Duration>,
}

impl<T: Zeroize> Secret<T> {
    /// Create a new secret wrapping the given value with no expiry.
    ///
    /// # Examples
    ///
    /// ```
    /// use philiprehberger_secret_store::Secret;
    ///
    /// let secret = Secret::new("password".to_string());
    /// ```
    pub fn new(value: T) -> Self {
        Self {
            inner: value,
            created_at: Instant::now(),
            ttl: None,
        }
    }

    /// Create a new secret with a time-to-live.
    ///
    /// After the TTL elapses, [`expose`](Secret::expose) will panic and
    /// [`expose_or`](Secret::expose_or) will return `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use philiprehberger_secret_store::Secret;
    /// use std::time::Duration;
    ///
    /// let secret = Secret::with_ttl("token".to_string(), Duration::from_secs(3600));
    /// assert!(!secret.is_expired());
    /// ```
    pub fn with_ttl(value: T, ttl: Duration) -> Self {
        Self {
            inner: value,
            created_at: Instant::now(),
            ttl: Some(ttl),
        }
    }

    /// Manually zeroize the inner value without dropping the secret.
    ///
    /// After calling this, the secret still exists but its value has been
    /// overwritten with zeroes.
    ///
    /// # Examples
    ///
    /// ```
    /// use philiprehberger_secret_store::Secret;
    ///
    /// let mut secret = Secret::new("sensitive".to_string());
    /// secret.clear();
    /// secret.expose(|v| assert!(v.is_empty()));
    /// ```
    pub fn clear(&mut self) {
        self.inner.zeroize();
    }

    /// Access the secret value through a closure.
    ///
    /// # Panics
    ///
    /// Panics if the secret has expired.
    ///
    /// # Examples
    ///
    /// ```
    /// use philiprehberger_secret_store::Secret;
    ///
    /// let secret = Secret::new(42u64);
    /// let doubled = secret.expose(|val| val * 2);
    /// assert_eq!(doubled, 84);
    /// ```
    #[must_use]
    pub fn expose<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        assert!(!self.is_expired(), "secret has expired");
        f(&self.inner)
    }

    /// Access the secret value, returning `None` if expired.
    ///
    /// # Examples
    ///
    /// ```
    /// use philiprehberger_secret_store::Secret;
    /// use std::time::Duration;
    ///
    /// let secret = Secret::with_ttl("value".to_string(), Duration::from_secs(3600));
    /// let result = secret.expose_or(|v| v.clone());
    /// assert!(result.is_some());
    /// ```
    #[must_use]
    pub fn expose_or<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&T) -> R,
    {
        if self.is_expired() {
            None
        } else {
            Some(f(&self.inner))
        }
    }

    /// Check whether the secret has exceeded its TTL.
    ///
    /// Returns `false` if no TTL was set.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        match self.ttl {
            Some(ttl) => self.created_at.elapsed() > ttl,
            None => false,
        }
    }

    /// Return the duration since this secret was created.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Check whether the secret is older than `max_age` and should be rotated.
    #[must_use]
    pub fn needs_rotation(&self, max_age: Duration) -> bool {
        self.age() > max_age
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(****)")
    }
}

impl<T: Zeroize + fmt::Display> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "****")
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            created_at: Instant::now(),
            ttl: self.ttl,
        }
    }
}

impl From<String> for Secret<String> {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for Secret<String> {
    fn from(value: &str) -> Self {
        Self::new(value.to_string())
    }
}

impl From<Vec<u8>> for Secret<Vec<u8>> {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

/// A secret holding a `String` value.
///
/// Provides additional constructors for loading secrets from environment variables.
pub type SecretString = Secret<String>;

impl SecretString {
    /// Load a secret from an environment variable, then immediately remove the variable.
    ///
    /// Returns `None` if the variable is not set.
    ///
    /// # Safety note
    ///
    /// This calls `std::env::remove_var` to prevent the secret from lingering
    /// in the process environment.
    pub fn from_env(key: &str) -> Option<SecretString> {
        match std::env::var(key) {
            Ok(value) => {
                // SAFETY: We are removing the env var to prevent leaking secrets.
                // This is intentional and the caller is expected to be aware of this.
                #[allow(unused_unsafe)]
                unsafe {
                    std::env::remove_var(key);
                }
                Some(SecretString::new(value))
            }
            Err(_) => None,
        }
    }

    /// Load a secret from an environment variable, returning an error if not set.
    ///
    /// The environment variable is removed after reading.
    pub fn from_env_required(key: &str) -> Result<SecretString, SecretError> {
        Self::from_env(key).ok_or_else(|| SecretError::EnvVarNotFound(key.to_string()))
    }
}

/// A secret holding a `Vec<u8>` value for binary secrets.
pub type SecretBytes = Secret<Vec<u8>>;

/// Errors that can occur when working with secrets.
#[derive(Debug)]
pub enum SecretError {
    /// The secret has expired past its TTL.
    Expired,
    /// The requested environment variable was not found.
    EnvVarNotFound(String),
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::Expired => write!(f, "secret has expired"),
            SecretError::EnvVarNotFound(key) => {
                write!(f, "environment variable not found: {key}")
            }
        }
    }
}

impl std::error::Error for SecretError {}

/// A keyed collection of [`SecretString`] values with expiry management.
///
/// # Examples
///
/// ```
/// use philiprehberger_secret_store::SecretStore;
///
/// let mut store = SecretStore::new();
/// store.insert("api_key", "sk-abc123");
///
/// assert_eq!(store.expose("api_key"), Some("sk-abc123".to_string()));
/// assert_eq!(store.len(), 1);
/// ```
pub struct SecretStore {
    secrets: HashMap<String, SecretString>,
}

impl SecretStore {
    /// Create a new empty secret store.
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }

    /// Insert a secret into the store.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.secrets
            .insert(key.into(), SecretString::new(value.into()));
    }

    /// Insert a secret with a time-to-live.
    pub fn insert_with_ttl(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
        ttl: Duration,
    ) {
        self.secrets
            .insert(key.into(), SecretString::with_ttl(value.into(), ttl));
    }

    /// Get a reference to a secret by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&SecretString> {
        self.secrets.get(key)
    }

    /// Convenience method: get a secret, expose it, and clone the string.
    ///
    /// Returns `None` if the key doesn't exist or the secret is expired.
    #[must_use]
    pub fn expose(&self, key: &str) -> Option<String> {
        self.secrets
            .get(key)
            .and_then(|s| s.expose_or(|v| v.clone()))
    }

    /// Remove a secret from the store. The value is zeroized on drop.
    pub fn remove(&mut self, key: &str) {
        self.secrets.remove(key);
    }

    /// Remove all expired secrets from the store.
    pub fn remove_expired(&mut self) {
        self.secrets.retain(|_, secret| !secret.is_expired());
    }

    /// Check if a key exists in the store.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.secrets.contains_key(key)
    }

    /// Remove and zeroize all secrets from the store.
    pub fn clear(&mut self) {
        self.secrets.clear();
    }

    /// Iterate over the keys in the store.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.secrets.keys().map(|k| k.as_str())
    }

    /// Return the number of secrets in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Check whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }
}

impl Default for SecretStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("SecretStore");
        for key in self.secrets.keys() {
            debug.field(key, &"****");
        }
        debug.finish()
    }
}

// --- Serde support ---

#[cfg(feature = "serde")]
mod serde_support {
    use super::*;
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl<T: Zeroize + Serialize> Serialize for Secret<T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str("****")
        }
    }

    impl<'de, T: Zeroize + DeserializeOwned> Deserialize<'de> for Secret<T> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let value = T::deserialize(deserializer)?;
            Ok(Secret::new(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_secret_new_and_expose() {
        let secret = Secret::new("hello".to_string());
        let val = secret.expose(|v| v.clone());
        assert_eq!(val, "hello");
    }

    #[test]
    fn test_debug_never_reveals_value() {
        let secret = Secret::new("super-secret".to_string());
        let debug = format!("{:?}", secret);
        assert_eq!(debug, "Secret(****)");
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn test_display_never_reveals_value() {
        let secret = Secret::new("super-secret".to_string());
        let display = format!("{}", secret);
        assert_eq!(display, "****");
        assert!(!display.contains("super-secret"));
    }

    #[test]
    #[should_panic(expected = "secret has expired")]
    fn test_expired_secret_panics_on_expose() {
        let secret = Secret::with_ttl("value".to_string(), Duration::from_millis(1));
        thread::sleep(Duration::from_millis(10));
        let _ = secret.expose(|_| {});
    }

    #[test]
    fn test_expose_or_returns_none_for_expired() {
        let secret = Secret::with_ttl("value".to_string(), Duration::from_millis(1));
        thread::sleep(Duration::from_millis(10));
        let result = secret.expose_or(|v| v.clone());
        assert!(result.is_none());
    }

    #[test]
    fn test_is_expired_with_short_ttl() {
        let secret = Secret::with_ttl("value".to_string(), Duration::from_millis(1));
        assert!(!secret.is_expired() || secret.is_expired()); // may or may not be expired yet
        thread::sleep(Duration::from_millis(10));
        assert!(secret.is_expired());
    }

    #[test]
    fn test_needs_rotation() {
        let secret = Secret::new("value".to_string());
        // Just created, should not need rotation with a long max_age
        assert!(!secret.needs_rotation(Duration::from_secs(3600)));
        // Should need rotation with a zero max_age
        thread::sleep(Duration::from_millis(5));
        assert!(secret.needs_rotation(Duration::from_millis(1)));
    }

    #[test]
    fn test_secret_string_from_env() {
        let key = "TEST_SECRET_STORE_ENV_VAR_12345";
        std::env::set_var(key, "my-secret-value");
        let secret = SecretString::from_env(key).expect("should find env var");
        // Env var should be removed
        assert!(std::env::var(key).is_err());
        // Value should be accessible
        let val = secret.expose(|v| v.clone());
        assert_eq!(val, "my-secret-value");
    }

    #[test]
    fn test_secret_string_from_env_required_missing() {
        let key = "TEST_SECRET_STORE_MISSING_VAR_99999";
        let result = SecretString::from_env_required(key);
        assert!(result.is_err());
        match result.unwrap_err() {
            SecretError::EnvVarNotFound(k) => assert_eq!(k, key),
            _ => panic!("expected EnvVarNotFound"),
        }
    }

    #[test]
    fn test_secret_store_insert_get_expose() {
        let mut store = SecretStore::new();
        store.insert("key1", "value1");
        store.insert("key2", "value2");

        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
        assert_eq!(store.expose("key1"), Some("value1".to_string()));
        assert_eq!(store.expose("key2"), Some("value2".to_string()));
        assert_eq!(store.expose("key3"), None);
    }

    #[test]
    fn test_secret_store_remove_expired() {
        let mut store = SecretStore::new();
        store.insert("permanent", "stays");
        store.insert_with_ttl("temporary", "goes", Duration::from_millis(1));

        assert_eq!(store.len(), 2);
        thread::sleep(Duration::from_millis(10));
        store.remove_expired();
        assert_eq!(store.len(), 1);
        assert_eq!(store.expose("permanent"), Some("stays".to_string()));
        assert_eq!(store.expose("temporary"), None);
    }

    #[test]
    fn test_secret_store_debug_shows_keys_not_values() {
        let mut store = SecretStore::new();
        store.insert("api_key", "sk-secret-123");
        let debug = format!("{:?}", store);
        assert!(debug.contains("api_key"));
        assert!(debug.contains("****"));
        assert!(!debug.contains("sk-secret-123"));
    }

    #[test]
    fn test_clone_resets_created_at() {
        let secret = Secret::new("value".to_string());
        thread::sleep(Duration::from_millis(10));
        let cloned = secret.clone();
        // The clone should be newer
        assert!(cloned.age() < secret.age());
    }

    #[test]
    fn test_drop_runs_zeroize() {
        // We can't easily inspect memory after drop, but we verify it compiles
        // and runs without error.
        let secret = Secret::new("sensitive-data".to_string());
        drop(secret);
    }

    #[test]
    fn test_secret_store_remove() {
        let mut store = SecretStore::new();
        store.insert("key", "value");
        assert_eq!(store.len(), 1);
        store.remove("key");
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn test_secret_store_keys() {
        let mut store = SecretStore::new();
        store.insert("a", "1");
        store.insert("b", "2");
        let mut keys: Vec<&str> = store.keys().collect();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[test]
    fn test_secret_bytes() {
        let secret = SecretBytes::new(vec![1, 2, 3, 4]);
        let val = secret.expose(|v| v.clone());
        assert_eq!(val, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_from_string() {
        let secret: Secret<String> = Secret::from("hello".to_string());
        let val = secret.expose(|v| v.clone());
        assert_eq!(val, "hello");
    }

    #[test]
    fn test_from_str() {
        let secret: Secret<String> = Secret::from("hello");
        let val = secret.expose(|v| v.clone());
        assert_eq!(val, "hello");
    }

    #[test]
    fn test_from_vec_u8() {
        let secret: SecretBytes = SecretBytes::from(vec![1, 2, 3]);
        let val = secret.expose(|v| v.clone());
        assert_eq!(val, vec![1, 2, 3]);
    }

    #[test]
    fn test_secret_store_contains_key() {
        let mut store = SecretStore::new();
        store.insert("key", "value");
        assert!(store.contains_key("key"));
        assert!(!store.contains_key("missing"));
    }

    #[test]
    fn test_secret_store_clear() {
        let mut store = SecretStore::new();
        store.insert("a", "1");
        store.insert("b", "2");
        assert_eq!(store.len(), 2);
        store.clear();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_secret_error_display() {
        let err = SecretError::Expired;
        assert_eq!(format!("{err}"), "secret has expired");

        let err = SecretError::EnvVarNotFound("MY_VAR".to_string());
        assert_eq!(format!("{err}"), "environment variable not found: MY_VAR");
    }
}

#[cfg(test)]
#[cfg(feature = "serde")]
mod serde_tests {
    use super::*;

    #[test]
    fn test_serialize_redacts() {
        let secret = Secret::new("real-value".to_string());
        let json = serde_json::to_string(&secret).unwrap();
        assert_eq!(json, r#""****""#);
        assert!(!json.contains("real-value"));
    }

    #[test]
    fn test_deserialize_secret_string() {
        let json = r#""my-secret""#;
        let secret: Secret<String> = serde_json::from_str(json).unwrap();
        let val = secret.expose(|v: &String| v.clone());
        assert_eq!(val, "my-secret");
    }
}
