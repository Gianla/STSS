//! Shared network protocol between the client and the server.

use const_format::concatcp;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use wincode::config::Configuration;
use wincode::{SchemaRead, SchemaWrite};

/// Sha256 type wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SchemaWrite, SchemaRead)]
pub struct Sha256Hash([u8; 32]);

impl Sha256Hash {
    pub fn from(raw_bytes: &[u8; 32]) -> Self {
        let raw_bytes_copy = *raw_bytes;

        Self(raw_bytes_copy)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Let the caller pass it anyway they want.
impl AsRef<[u8]> for Sha256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Convert Sha256's ugly output type into ours.
impl From<sha2::digest::Output<Sha256>> for Sha256Hash {
    fn from(output: sha2::digest::Output<Sha256>) -> Self {
        Sha256Hash(output.into())
    }
}

pub const RSA_KEY_SIZE_IN_BITS: usize = 2048;
pub const RSA_KEY_SIZE_IN_BYTES: usize = RSA_KEY_SIZE_IN_BITS / 8;

/// Abstract the RSA signature.
#[derive(Debug, PartialEq, Eq, SchemaWrite, SchemaRead)]
pub struct RsaSignature([u8; RSA_KEY_SIZE_IN_BYTES]);

impl RsaSignature {
    pub fn as_bytes(&self) -> &[u8; RSA_KEY_SIZE_IN_BYTES] {
        &self.0
    }
}

impl From<[u8; RSA_KEY_SIZE_IN_BYTES]> for RsaSignature {
    fn from(value: [u8; RSA_KEY_SIZE_IN_BYTES]) -> Self {
        RsaSignature(value)
    }
}

impl AsRef<[u8]> for RsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Error to use when converting a vector into a signature.
#[derive(Debug, Error)]
#[error(
    "the specified value cannot be converted into an RSA signature since it has length {0} bits"
)]
pub struct InvalidLengthForRsaSignature(usize);

impl TryFrom<&[u8]> for RsaSignature {
    type Error = InvalidLengthForRsaSignature;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; RSA_KEY_SIZE_IN_BYTES] = value
            .try_into()
            .map_err(|_| InvalidLengthForRsaSignature(value.len()))?;

        Ok(Self(arr))
    }
}

impl From<&[u8; RSA_KEY_SIZE_IN_BYTES]> for RsaSignature {
    fn from(value: &[u8; RSA_KEY_SIZE_IN_BYTES]) -> Self {
        Self(*value)
    }
}

/// Timestamp type wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SchemaWrite, SchemaRead)]
pub struct Timestamp(u128);

impl Timestamp {
    pub fn new(n: u128) -> Self {
        Self(n)
    }

    pub fn from_be(be_array: [u8; 16]) -> Self {
        let raw_value = u128::from_be_bytes(be_array);

        Self::new(raw_value)
    }

    pub fn get(&self) -> u128 {
        self.0
    }

    pub fn as_bytes(&self) -> [u8; 16] {
        self.0.to_ne_bytes()
    }

    pub fn as_be_bytes(&self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

impl From<[u8; 16]> for Timestamp {
    fn from(value: [u8; 16]) -> Self {
        Self::new(u128::from_be_bytes(value))
    }
}

impl TryFrom<i64> for Timestamp {
    type Error = ();

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        if value < 0 {
            Err(())
        } else {
            Ok(Self(value as u128))
        }
    }
}

/// Main function used to sign a hash.
#[inline(always)]
pub fn sign_with_timestamp(
    signing_key: &RsaPrivateKey,
    hash_to_sign: Sha256Hash,
    timestamp: Timestamp,
) -> Result<RsaSignature, rsa::Error> {
    let mut hasher = Sha256::new();

    hasher.update(hash_to_sign.as_bytes());
    hasher.update(timestamp.get().to_be_bytes());

    let combined_hash: Sha256Hash = hasher.finalize().into();
    let padding = Pkcs1v15Sign::new::<Sha256>();

    let signature_vec: Vec<u8> = signing_key.sign(padding, combined_hash.as_bytes())?;

    let signature_array: [u8; RSA_KEY_SIZE_IN_BYTES] = signature_vec.try_into().expect(concatcp!(
        "cryptographic invariant violated, RSA ensures that {} is a valid key size",
        RSA_KEY_SIZE_IN_BYTES
    ));

    Ok(RsaSignature(signature_array))
}

/// Verify a signature.
#[inline(always)]
pub fn verify_timestamp_signature(
    public_key: impl AsRef<RsaPublicKey>,
    hash_to_verify: Sha256Hash,
    timestamp: Timestamp,
    signature: &RsaSignature,
) -> Result<(), rsa::Error> {
    let mut hasher = Sha256::new();

    hasher.update(hash_to_verify.as_bytes());
    hasher.update(timestamp.get().to_be_bytes());

    let combined_hash: Sha256Hash = hasher.finalize().into();

    let padding = Pkcs1v15Sign::new::<Sha256>();

    public_key
        .as_ref()
        .verify(padding, combined_hash.as_bytes(), signature.as_ref())
}

/// Used when a user asks their history record(s).
#[derive(Debug, PartialEq, Eq, SchemaWrite, SchemaRead)]
pub struct HistoryRecord {
    sign: RsaSignature,
    timestamp: Timestamp,
}

impl HistoryRecord {
    pub fn new(hash: RsaSignature, timestamp: Timestamp) -> Self {
        Self {
            sign: hash,
            timestamp,
        }
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub fn timestamp_as_u128(&self) -> u128 {
        self.timestamp.0
    }

    pub fn hash(&self) -> &RsaSignature {
        &self.sign
    }
}

/// Possible errors when a user try to log in.
#[derive(Error, Debug, SchemaWrite, SchemaRead)]
pub enum LoginError {
    #[error("Wrong username or password.")]
    InvalidCredentials,

    #[error("You are already logged in. Please consider logging out and retry.")]
    AlreadyLoggedIn,
}

/// Possible errors when a new user try to sign in.
#[derive(Error, Debug, SchemaWrite, SchemaRead)]
pub enum SignInError {
    #[error("The username you provided was already taken. Please provide another one.")]
    UsernameAlreadyTaken,

    #[error("You are already logged in. Please consider logging out and retry.")]
    AlreadyLoggedIn,
}

/// Requests sent by the client.
#[derive(Debug, SchemaWrite, SchemaRead)]
pub enum Request {
    Login(String, String),
    SignUp(String, String),
    LogOut,
    SignHash(Sha256Hash),
    PurchaseTokens(u64),
    HowManyTokensDoIHave,
    History,
}

/// Responses sent by the server.
#[derive(Debug, SchemaWrite, SchemaRead)]
pub enum Response {
    Ok,
    LoginFailed(LoginError),
    SignInFailed(SignInError),
    NotLoggedIn,
    TokenCount(u64),
    TokenAmountTooHigh,
    NotEnoughTokens,
    Token {
        sign: Box<RsaSignature>,
        timestamp: Timestamp,
    },
    OperationError(String),
    History(Vec<HistoryRecord>),
}

/// Wrapper around wincode::WriteError.
#[derive(Debug, Error)]
#[error("wincode write error: {0}")]
pub struct SerializeError(#[from] wincode::WriteError);

/// Wrapper around wincode::ReadError.
#[derive(Debug, Error)]
#[error("wincode read error: {0}")]
pub struct DeserializeError(#[from] wincode::ReadError);

const MAX_ALLOCATION_SIZE: usize = 4 * 1024 * 1024;

/// This formalizes the structure of our protocol.
const BINCODE_CONFIG: Configuration<
    true,
    MAX_ALLOCATION_SIZE,
    wincode::len::UseIntLen<u64, 0>,
    wincode::int_encoding::BigEndian,
> = Configuration::default()
    .with_big_endian()
    .with_fixint_encoding();

macro_rules! impl_network_message {
    ($t:ty) => {
        impl $t {
            pub fn serialize(&self) -> Result<bytes::Bytes, SerializeError> {
                wincode::config::serialize(self, BINCODE_CONFIG)
                    .map(bytes::Bytes::from)
                    .map_err(SerializeError)
            }

            pub fn deserialize(bytes: impl AsRef<[u8]>) -> Result<$t, DeserializeError> {
                wincode::config::deserialize(bytes.as_ref(), BINCODE_CONFIG)
                    .map_err(DeserializeError)
            }
        }
    };
}

impl_network_message!(Request);
impl_network_message!(Response);
