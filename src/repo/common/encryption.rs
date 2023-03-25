use std::fmt::{self, Debug, Formatter};

use secrecy::{DebugSecret, ExposeSecret, Secret, SecretVec};
use serde::{Deserialize, Serialize};

#[cfg(feature = "encryption")]
use {
    rand::{rngs::OsRng, RngCore},
};

/// A limit on the resources used by a key derivation function.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub enum ResourceLimit {
    /// Suitable for interactive use.
    Interactive,

    /// Suitable for moderately sensitive data.
    Moderate,

    /// Suitable for highly sensitive data.
    Sensitive,
}

impl ResourceLimit {
    /// Get a memory limit based on this resource limit.
    #[cfg(feature = "encryption")]
    fn to_mem_limit(self) -> u32 {
        match self {
            ResourceLimit::Interactive => 65536,
            ResourceLimit::Moderate => 262144,
            ResourceLimit::Sensitive => 1048576,
        }
    }

    /// Get an operations limit based on this resource limit.
    #[cfg(feature = "encryption")]
    fn to_ops_limit(self) -> u32 {
        match self {
            ResourceLimit::Interactive => 2,
            ResourceLimit::Moderate => 3,
            ResourceLimit::Sensitive => 4,
        }
    }
}

/// A data encryption method.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Encryption {
    /// Do not encrypt data.
    None,

    /// Encrypt data using the AES-GCM-256 cipher.
    #[cfg(feature = "encryption")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    AesGcm256,
}

const NONCEBYTES: usize = 12;
const KEYBYTES: usize = 32;

impl Encryption {
    /// Encrypt the given `cleartext` with the given `key`.
    #[cfg(feature = "encryption")]
    pub(crate) fn encrypt(&self, cleartext: &[u8], key: &EncryptionKey) -> Vec<u8> {
        use aes_gcm::{aead::Aead, KeyInit};

        match self {
            Encryption::None => cleartext.to_vec(),
            Encryption::AesGcm256 => {
                let mut nonce = [0u8; NONCEBYTES];
                OsRng.fill_bytes(&mut nonce);
                let aes_nonce = aes_gcm::Nonce::from_slice(&nonce);
                let aes_key = aes_gcm::Aes256Gcm::new_from_slice(key.expose_secret()).unwrap();
                let mut ciphertext = aes_key.encrypt(aes_nonce, cleartext).unwrap();
                let mut output = nonce.to_vec();
                output.append(&mut ciphertext);
                output
            }
        }
    }

    /// Encrypt the given `cleartext` with the given `key`.
    #[cfg(not(feature = "encryption"))]
    pub(crate) fn encrypt(&self, cleartext: &[u8], _key: &EncryptionKey) -> Vec<u8> {
        cleartext.to_vec()
    }

    /// Decrypt the given `ciphertext` with the given `key`.
    #[cfg(feature = "encryption")]
    pub(crate) fn decrypt(&self, ciphertext: &[u8], key: &EncryptionKey) -> crate::Result<Vec<u8>> {
        use aes_gcm::{aead::Aead, KeyInit};

        match self {
            Encryption::None => Ok(ciphertext.to_vec()),
            Encryption::AesGcm256 => {
                let aes_nonce = aes_gcm::Nonce::from_slice(&ciphertext[..NONCEBYTES]);
                let aes_key = aes_gcm::Aes256Gcm::new_from_slice(key.expose_secret()).unwrap();
                aes_key.decrypt(aes_nonce,&ciphertext[NONCEBYTES..])
                    .map_err(|_| crate::Error::InvalidData)
            }
        }
    }

    /// Decrypt the given `ciphertext` with the given `key`.
    #[cfg(not(feature = "encryption"))]
    pub(crate) fn decrypt(
        &self,
        ciphertext: &[u8],
        _key: &EncryptionKey,
    ) -> crate::Result<Vec<u8>> {
        Ok(ciphertext.to_vec())
    }
}

impl Encryption {
    /// The key size for this encryption method.
    pub(crate) fn key_size(&self) -> usize {
        match self {
            Encryption::None => 0,
            #[cfg(feature = "encryption")]
            Encryption::AesGcm256 => KEYBYTES,
        }
    }
}

/// Salt for deriving an encryption `Key`.
///
/// This type can be serialized to persistently store the salt.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeySalt(pub(crate) Vec<u8>);

impl KeySalt {
    /// Generate a new empty `KeySalt`.
    pub fn empty() -> Self {
        KeySalt(Vec::new())
    }

    /// Generate a new random `KeySalt`.
    #[cfg(feature = "encryption")]
    pub fn generate() -> Self {
        let mut salt = [0u8; argon2::RECOMMENDED_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        KeySalt(salt.to_vec())
    }

    #[cfg(not(feature = "encryption"))]
    pub fn generate() -> Self {
        panic!("The `encryption` cargo feature is not enabled.")
    }
}

/// An secret encryption key.
///
/// The bytes of the key are zeroed in memory when this value is dropped.
pub struct EncryptionKey(SecretVec<u8>);

impl DebugSecret for EncryptionKey {}

impl Debug for EncryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Self::debug_secret(f)
    }
}

impl ExposeSecret<Vec<u8>> for EncryptionKey {
    fn expose_secret(&self) -> &Vec<u8> {
        self.0.expose_secret()
    }
}

impl EncryptionKey {
    /// Create an encryption key containing the given `bytes`.
    pub fn new(bytes: Vec<u8>) -> Self {
        EncryptionKey(Secret::new(bytes))
    }

    /// Generate a new random encryption key of the given `size`.
    ///
    /// This uses bytes retrieved from the operating system's cryptographically secure random number
    /// generator.
    #[cfg(feature = "encryption")]
    pub fn generate(size: usize) -> Self {
        let mut bytes = vec![0u8; size];
        OsRng.fill_bytes(&mut bytes);
        EncryptionKey::new(bytes)
    }

    #[cfg(not(feature = "encryption"))]
    pub fn generate(_size: usize) -> Self {
        panic!("The `encryption` cargo feature is not enabled.")
    }

    /// Derive a new encryption key of the given `size` from the given `password` and `salt`.
    ///
    /// This uses the Argon2id key derivation function.
    #[cfg(feature = "encryption")]
    pub fn derive(
        password: &[u8],
        salt: &KeySalt,
        size: usize,
        memory: ResourceLimit,
        operations: ResourceLimit,
    ) -> Self {
        let mut bytes = vec![0u8; size];
        let params = argon2::Params::new(memory.to_mem_limit(), operations.to_ops_limit(), 1, None).unwrap();
        let key_stretcher = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        key_stretcher.hash_password_into(password, salt.0.as_slice(), &mut bytes).expect("failed to derive an encryption key.");
        EncryptionKey::new(bytes)
    }

    #[cfg(not(feature = "encryption"))]
    pub fn derive(
        _password: &[u8],
        _salt: &KeySalt,
        _size: usize,
        _memory: ResourceLimit,
        _operations: ResourceLimit,
    ) -> Self {
        panic!("The `encryption` cargo feature is not enabled.")
    }
}
