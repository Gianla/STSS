//! Shared network protocol between the client and the server.

use thiserror::Error;
use wincode::config::Configuration;
use wincode::{ReadResult, SchemaRead, SchemaWrite, WriteResult};

/// Timestamp type wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SchemaWrite, SchemaRead)]
pub struct Timestamp(u128);

impl Timestamp {
    pub fn from(n: u128) -> Self {
        Self(n)
    }

    pub fn get(&self) -> u128 {
        self.0
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
    SignHash([u8; 32]),
    PurchaseTokens(u64),
    HowManyTokensDoIHave,
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
    Token { sign: Vec<u8>, timestamp: Timestamp },
    OperationError(String),
}

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
            pub fn serialize(&self) -> WriteResult<bytes::Bytes> {
                wincode::config::serialize(self, BINCODE_CONFIG).map(bytes::Bytes::from)
            }

            pub fn deserialize(bytes: impl AsRef<[u8]>) -> ReadResult<$t> {
                wincode::config::deserialize(bytes.as_ref(), BINCODE_CONFIG)
            }
        }
    };
}

impl_network_message!(Request);
impl_network_message!(Response);
