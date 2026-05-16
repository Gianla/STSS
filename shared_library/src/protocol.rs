//! Shared network protocol between the client and the server.

use thiserror::Error;
use rkyv::{Archive, Serialize, Deserialize};
use crate::network_numbers::{NetworkLongLong};

/// Possible errors when a user try to log in.
#[derive(Archive, Error, Debug)]
pub enum LoginError {
    #[error("username {0:?} was not found")]
    UsernameNotFound(String)
}

/// Possible errors when a new user try to sign in.
#[derive(Archive, Error, Debug)]
pub enum SignInError {
    #[error("username {0:?} is already taken")]
    UsernameAlreadyTaken(String)
}

/// Requests sent by the client.
#[derive(Archive, Serialize, Deserialize, Debug)]
pub enum Request {
    /* we use structs to differentiate between username and password. */
    Login(String, String),
    SignUp(String, String),
    SignHash(String),   // todo: change hash from String into a simple SignRequest(SomeHashType)
    PurchaseTokens(NetworkLongLong),
    HowManyTokensDoIHave,
}

/// Responses sent by the server.
#[derive(Archive, Serialize, Deserialize, Debug)]
pub enum Response {
    Ok,
    LoginFailed(LoginError),
    SignInFailed(SignInError),
    TokenCount(NetworkLongLong),
    Token(String, u64), // token and signed_at. todo: change the types here too
}
