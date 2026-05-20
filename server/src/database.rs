//! Contains the database structure and the utils to interact with it, all in a thread-safe and
//! coroutine-safe fashion.

use std::{fs, io};
use std::path::PathBuf;
use sqlx::{FromRow, SqlitePool};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteQueryResult};
use thiserror::Error;
use futures::executor::block_on;
use argon2::{password_hash::{PasswordHash, PasswordVerifier}, Argon2, PasswordHasher};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use futures::TryStreamExt;

pub enum DataBaseLocation {
    Disk(PathBuf),
    Memory,
}

/// Possible errors that might arise while performing database operations.
#[derive(Error, Debug)]
pub enum InternalDataBaseError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),

    #[error("error while parsing the hash: {0}, maybe the database is corrupted")]
    Hash(#[from] argon2::password_hash::Error),
}


/// Possible errors when a user tries to authenticate.
#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("user {0:?} was not found")]
    UserNotFound(String),

    #[error("invalid password")]
    InvalidPassword,

    #[error(transparent)]
    InternalDataBase(#[from] InternalDataBaseError)
}

/// Possible errors when a user tries to sing in.
#[derive(Error, Debug)]
pub enum RegistrationError {
    #[error("user {0:?} already exists")]
    UserAlreadyExists(String),

    #[error(transparent)]
    InternalDataBase(#[from] InternalDataBaseError)
}

/// Possible errors when trying to extract a user's tokens.
#[derive(Error, Debug)]
pub enum GetTokensError {
    #[error("user does not exist")]
    UserDoesNotExist,

    #[error("user {0} has an invalid amount of token: {1}")]
    TokenIntegrityCheckViolated(String, i64),

    #[error(transparent)]
    InternalDataBase(#[from] InternalDataBaseError),
}

/// To directly convert a GetTokensError into an InternalDataBaseError.
impl From<sqlx::Error> for GetTokensError {
    fn from(err: sqlx::Error) -> Self {
        GetTokensError::InternalDataBase(InternalDataBaseError::Sql(err))
    }
}

/// Errors that can happen only when ADDING tokens.
#[derive(Error, Debug)]
pub enum AddTokensError {
    #[error("user does not exist")]
    UserDoesNotExist,

    #[error("too many tokens (overflow)")]
    TokenOverflow,

    #[error(transparent)]
    InternalDataBase(#[from] InternalDataBaseError),
}

/// Errors that can happen only when SUBTRACTING tokens.
#[derive(Error, Debug)]
pub enum SubtractTokensError {
    #[error("user does not exist")]
    UserDoesNotExist,

    #[error("insufficient tokens to complete the operation")]
    InsufficientTokens,

    #[error(transparent)]
    InternalDataBase(#[from] InternalDataBaseError),
}

/// To directly convert a UpdateTokensError into an InternalDataBaseError.
impl From<sqlx::Error> for AddTokensError {
    fn from(err: sqlx::Error) -> Self {
        AddTokensError::InternalDataBase(InternalDataBaseError::Sql(err))
    }
}

/// To directly convert a UpdateTokensError into an InternalDataBaseError.
impl From<sqlx::Error> for SubtractTokensError {
    fn from(err: sqlx::Error) -> Self {
        SubtractTokensError::InternalDataBase(InternalDataBaseError::Sql(err))
    }
}

#[derive(Clone)]
pub struct ServerDataBase {
    connection_pool: SqlitePool,
    verifier: Argon2<'static>,
}

impl ServerDataBase {
    fn internal_new(connection_pool: SqlitePool) -> Self {
        Self { connection_pool, verifier: Argon2::default() }
    }

    pub async fn verify_user_password(
        &self,
        username: impl AsRef<str>,
        plain_password: impl AsRef<str>,
    ) -> Result<(), AuthenticationError> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT password_hash FROM users WHERE username = ? LIMIT 1;"
        )
            .bind(username.as_ref())
            .fetch_optional(&self.connection_pool)
            .await
            .map_err(InternalDataBaseError::Sql)?;

        let (stored_hash,) = match row {
            Some(data) => data,
            None => return Err(AuthenticationError::UserNotFound(username.as_ref().to_string())),
        };

        let parsed_hash = PasswordHash::new(&stored_hash)
            .map_err(InternalDataBaseError::Hash)?;

        match self.verifier.verify_password(plain_password.as_ref().as_bytes(), &parsed_hash) {
            Ok(_) => Ok(()),
            Err(_) => Err(AuthenticationError::InvalidPassword),
        }
    }

    pub async fn try_register_user(
        &self,
        username: impl AsRef<str>,
        plain_password: impl AsRef<str>,
    ) -> Result<(), RegistrationError> {
        let username_ref = username.as_ref();
        let password_ref = plain_password.as_ref();

        let salt = SaltString::generate(&mut OsRng);

        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password_ref.as_bytes(), &salt)
            .map_err(InternalDataBaseError::Hash)?
            .to_string();

        let result = sqlx::query(
            "INSERT INTO users (username, password_hash, available_tokens) VALUES (?, ?, ?);"
        )
            .bind(username_ref)
            .bind(&password_hash)
            .bind(0)
            .execute(&self.connection_pool)
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Err(RegistrationError::UserAlreadyExists(username_ref.to_string()))
            }
            Err(e) => Err(RegistrationError::InternalDataBase(InternalDataBaseError::Sql(e))),
        }
    }

    pub async fn get_user_tokens(&self, username: impl AsRef<str>) -> Result<u64, GetTokensError> {
        let query_result: Option<i64> = sqlx::query_scalar(
            "SELECT available_tokens FROM users WHERE username = $1"
        )
            .bind(username.as_ref())
            .fetch_optional(&self.connection_pool)
            .await?;

        if let Some(tokens) = query_result {
            if tokens < 0 {
                Err(GetTokensError::TokenIntegrityCheckViolated(
                    username.as_ref().to_string(), tokens
                ))
            } else {
                Ok(tokens as u64)
            }
        } else {
            Err( GetTokensError::UserDoesNotExist )
        }
    }

    pub async fn add_user_tokens(&self, username: &str, amount_u64: u64) -> Result<u64, AddTokensError> {
        let amount: i64 = amount_u64
            .try_into()
            .map_err(|_| AddTokensError::TokenOverflow)?;

        let mut tx = self.connection_pool.begin().await?;

        let current_tokens: Option<i64> = sqlx::query_scalar(
            "SELECT available_tokens FROM users WHERE username = $1 FOR UPDATE"
        )
            .bind(username)
            .fetch_optional(&mut *tx)
            .await?;

        let tokens = match current_tokens {
            None => return Err(AddTokensError::UserDoesNotExist),
            Some(t) => t,
        };

        let resulting_tokens = tokens
            .checked_add(amount)
            .ok_or(AddTokensError::TokenOverflow)?;

        sqlx::query(
            "UPDATE users SET available_tokens = available_tokens + $1 WHERE username = $2"
        )
            .bind(amount)
            .bind(username)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(resulting_tokens as u64)
    }

    pub async fn subtract_user_tokens(&self, username: &str, amount_u64: u64) -> Result<u64, SubtractTokensError> {
        let amount: i64 = amount_u64
            .try_into()
            .map_err(|_| SubtractTokensError::InsufficientTokens)?;

        let mut tx = self.connection_pool.begin().await?;

        let current_tokens: Option<i64> = sqlx::query_scalar(
            "SELECT available_tokens FROM users WHERE username = $1 FOR UPDATE"
        )
            .bind(username)
            .fetch_optional(&mut *tx)
            .await?;

        let tokens = match current_tokens {
            None => return Err(SubtractTokensError::UserDoesNotExist),
            Some(t) => t,
        };

        let resulting_tokens = tokens
            .checked_sub(amount)
            .ok_or(SubtractTokensError::InsufficientTokens)?;

        if resulting_tokens < 0 {
            return Err(SubtractTokensError::InsufficientTokens);
        }

        sqlx::query(
            "UPDATE users SET available_tokens = available_tokens - $1 WHERE username = $2"
        )
            .bind(amount)
            .bind(username)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(resulting_tokens as u64)
    }
}

/// Possible errors while properly building the database.
#[derive(Error, Debug)]
pub enum DataBaseBuildError {
    #[error("the specified database is invalid: test query {0:?} failed")]
    Validation(String),

    #[error("user {0:?} violates the constraint")]
    ConstraintViolation(String),

    #[error(transparent)]
    Sqlite(#[from] sqlx::Error),

    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Main structure to build the database and perform validation on an existing one, or
/// initialization on a new one.
pub struct ServerDataBaseBuilder {
    connection_pool: SqlitePool,
    initialization_is_required: bool,
}

impl ServerDataBaseBuilder {
    /// Builds the database connecting to a given one or creating it.
    /// Even if the underlying engine uses sqlx, an async library, this method abstracts the
    /// asynchronous complexity by creating a small runtime to execute asynchronous functions
    /// in order, thus we call it blocking_build().
    pub fn blocking_build(location: DataBaseLocation) -> Result<ServerDataBase, DataBaseBuildError> {
        let build = block_on(async {
            let mut build_ctx = Self::unchecked_build(location).await?;

            if build_ctx.initialization_is_required {
                build_ctx.initialize_db().await?;
            } else {
                build_ctx.validate().await?;
            }

            Ok::<_, DataBaseBuildError>(build_ctx)
        })?;

        Ok(ServerDataBase::internal_new(build.connection_pool))
    }

    /// Builds a ServerDataBase without checking the right conditions, avoiding performance losses
    /// but introducing to runtime risks.
    /// If used with checking functions, it becomes safe: the main constructor does that.
    async fn unchecked_build(location: DataBaseLocation) -> Result<Self, DataBaseBuildError> {
        let connection_options = SqliteConnectOptions::new()
            .pragma("foreign_keys", "ON");

        let mut initialization_is_required = false;

        let connection_options = match location {
            DataBaseLocation::Disk(path) => {
                if !path.exists() {
                    if let Some(parent) = path.parent() {
                        if !parent.to_string_lossy().is_empty() && !parent.exists() {
                            fs::create_dir_all(parent)?;
                        }
                    }
                    initialization_is_required = true;
                }
                connection_options
                    .filename(path)
                    .create_if_missing(true)
            },
            DataBaseLocation::Memory => {
                initialization_is_required = true;
                connection_options.in_memory(true)
            },
        };

        let connection_pool = SqlitePoolOptions::new()
            .connect_with(connection_options)
            .await?;

        Ok(
            Self {
                connection_pool,
                initialization_is_required
            }
        )
    }

    /// Required when in need to initialize the database, e.g. when it doesn't exist, or it is
    /// directly hosted in memory.
    async fn initialize_db(&mut self) -> Result<(), DataBaseBuildError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                available_tokens INTEGER NOT NULL CHECK (available_tokens >= 0),
                registered_from_ip TEXT NOT NULL,
            );

            CREATE TABLE IF NOT EXISTS history (
                username TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                hash TEXT NOT NULL,

                PRIMARY KEY (username, timestamp),
                CONSTRAINT fk_user FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
            );
            "#,
        )
            .execute(&self.connection_pool)
            .await?;

        self.initialization_is_required = false;
        Ok(())
    }

    /// Validates an already existing database through validation queries.
    async fn validate(&self) -> Result<(), DataBaseBuildError> {
        let validation_queries = vec![
            "SELECT username, password_hash, available_tokens FROM users LIMIT 1",
            "SELECT username, timestamp, hash FROM history LIMIT 1;"
        ];

        for query in validation_queries {
            if sqlx::query(query).execute(&self.connection_pool).await.is_err() {
                return Err(DataBaseBuildError::Validation(query.to_string()));
            }
        };

        #[derive(Debug, FromRow)]
        struct UserAudit {
            username: String,
            available_tokens: i32,
            is_valid: bool,
        }

        let mut rows_stream = sqlx::query_as::<_, UserAudit>(
            r#"
            SELECT
                username,
                available_tokens,
                (available_tokens >= 0) AS "is_valid!"
            FROM users
            "#
        )
            .fetch(&self.connection_pool);

        while let Some(row) = rows_stream.try_next().await? {
            if !row.is_valid {
                DataBaseBuildError::ConstraintViolation(row.username);
            }
        }

        Ok(())
    }
}
