//! Shared network protocol between the client and the server.

use thiserror::Error;
use wincode::{ReadResult, SchemaRead, SchemaWrite, WriteResult};

use crate::network_numbers::NetworkLongLong;

/// Possible errors when a user try to log in.
#[derive(Error, Debug, SchemaWrite, SchemaRead)]
pub enum LoginError {
    #[error(
        "The username you provided wasn't found. Please provide an existing one, or consider \
             signin in."
    )]
    UsernameNotFound,

    #[error("The password you provided was incorrect.")]
    InvalidPassword,

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
    SignHash(String), // todo: change hash from String into a simple SignRequest(SomeHashType)
    PurchaseTokens(NetworkLongLong),
    HowManyTokensDoIHave,
}

/// Responses sent by the server.
#[derive(Debug, SchemaWrite, SchemaRead)]
pub enum Response {
    Ok,
    LoginFailed(LoginError),
    SignInFailed(SignInError),
    NotLoggedIn,
    TokenCount(NetworkLongLong),
    TokenAmountTooHigh(NetworkLongLong),
    Token(String, u64), // token and signed_at. todo: change the types here too
}

macro_rules! impl_network_message {
    ($t:ty) => {
        impl $t {
            pub fn serialize(&self) -> WriteResult<bytes::Bytes> {
                wincode::serialize(self).map(bytes::Bytes::from)
            }

            pub fn deserialize(bytes: impl AsRef<[u8]>) -> ReadResult<$t> {
                wincode::deserialize(bytes.as_ref())
            }
        }
    };
}

impl_network_message!(Request);
impl_network_message!(Response);
