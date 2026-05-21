//! Contains the database structure and the utils to interact with it, all in a thread-safe and
//! coroutine-safe fashion.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2, PasswordHasher,
};
use futures::executor::block_on;
use futures::TryStreamExt;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{FromRow, SqlitePool};
use std::path::PathBuf;
use std::{fs, io};
use std::net::IpAddr;
use thiserror::Error;

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
    InternalDataBase(#[from] InternalDataBaseError),
}

/// Possible errors when a user tries to sing in.
#[derive(Error, Debug)]
pub enum RegistrationError {
    #[error("user {0:?} already exists")]
    UserAlreadyExists(String),

    #[error(transparent)]
    InternalDataBase(#[from] InternalDataBaseError),
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

/// Holds the Server's database. This struct will have to be clonable in a cheap way.
#[derive(Clone, Debug)]
pub struct ServerDataBase {
    // SqlitePool holds under the hood an Arc<> reference. It will be then easy to clone.
    connection_pool: SqlitePool,
    // Argon2 is a small structure. Benchmarking showed that cloning the raw structure is far more
    // efficient than cloning an Arc<> and a bit faster than building the default() everytime.
    verifier: Argon2<'static>,
}

impl ServerDataBase {
    fn internal_new(connection_pool: SqlitePool) -> Self {
        let verifier = Argon2::default();

        Self {
            connection_pool,
            verifier,
        }
    }

    pub async fn verify_user_password(
        &self,
        username: impl AsRef<str>,
        plain_password: impl AsRef<str>,
    ) -> Result<(), AuthenticationError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT password_hash FROM users WHERE username = ? LIMIT 1;")
                .bind(username.as_ref())
                .fetch_optional(&self.connection_pool)
                .await
                .map_err(InternalDataBaseError::Sql)?;

        let (stored_hash,) = match row {
            Some(data) => data,
            None => {
                return Err(AuthenticationError::UserNotFound(
                    username.as_ref().to_string(),
                ))
            }
        };

        let parsed_hash = PasswordHash::new(&stored_hash).map_err(InternalDataBaseError::Hash)?;

        match self.verifier.verify_password(plain_password.as_ref().as_bytes(), &parsed_hash) {
            Ok(_) => Ok(()),
            Err(_) => Err(AuthenticationError::InvalidPassword),
        }
    }

    pub async fn try_register_user(
        &self,
        username: impl AsRef<str>,
        plain_password: impl AsRef<str>,
        ip: IpAddr,
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
            "INSERT INTO users (username, password_hash, available_tokens, registered_from_ip) VALUES (?, ?, ?, ?);",
        )
        .bind(username_ref)
        .bind(&password_hash)
        .bind(0)
        .bind(ip.to_string())
        .execute(&self.connection_pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => Err(
                RegistrationError::UserAlreadyExists(username_ref.to_string()),
            ),
            Err(e) => Err(RegistrationError::InternalDataBase(
                InternalDataBaseError::Sql(e),
            )),
        }
    }

    pub async fn get_user_tokens(&self, username: impl AsRef<str>) -> Result<u64, GetTokensError> {
        let query_result: Option<i64> =
            sqlx::query_scalar("SELECT available_tokens FROM users WHERE username = $1")
                .bind(username.as_ref())
                .fetch_optional(&self.connection_pool)
                .await?;

        if let Some(tokens) = query_result {
            if tokens < 0 {
                Err(GetTokensError::TokenIntegrityCheckViolated(
                    username.as_ref().to_string(),
                    tokens,
                ))
            } else {
                Ok(tokens as u64)
            }
        } else {
            Err(GetTokensError::UserDoesNotExist)
        }
    }

    pub async fn add_user_tokens(
        &self,
        username: impl AsRef<str>,
        amount_u64: u64,
    ) -> Result<u64, AddTokensError> {
        let amount: i64 = amount_u64
            .try_into()
            .map_err(|_| AddTokensError::TokenOverflow)?;

        let mut tx = self.connection_pool.begin().await?;

        let current_tokens: Option<i64> =
            sqlx::query_scalar("SELECT available_tokens FROM users WHERE username = $1")
                .bind(username.as_ref())
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
            "UPDATE users SET available_tokens = available_tokens + $1 WHERE username = $2",
        )
        .bind(amount)
        .bind(username.as_ref())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(resulting_tokens as u64)
    }

    pub async fn subtract_user_tokens(
        &self,
        username: &str,
        amount_u64: u64,
    ) -> Result<u64, SubtractTokensError> {
        let amount: i64 = amount_u64
            .try_into()
            .map_err(|_| SubtractTokensError::InsufficientTokens)?;

        let mut tx = self.connection_pool.begin().await?;

        let current_tokens: Option<i64> =
            sqlx::query_scalar("SELECT available_tokens FROM users WHERE username = $1")
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
            "UPDATE users SET available_tokens = available_tokens - $1 WHERE username = $2",
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

    #[error("unexpected table found in the database: {0}")]
    UnexpectedTable(String),

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
    pub fn blocking_build(
        location: DataBaseLocation,
    ) -> Result<ServerDataBase, DataBaseBuildError> {
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
    /// but introducing runtime risks.
    /// If used with checking functions, it becomes safe: the main constructor does that.

    async fn unchecked_build(location: DataBaseLocation) -> Result<Self, DataBaseBuildError> {
        let connection_options = SqliteConnectOptions::new().pragma("foreign_keys", "ON");
        let mut pool_options = SqlitePoolOptions::new();

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
                connection_options.filename(path).create_if_missing(true)
            }
            DataBaseLocation::Memory => {
                initialization_is_required = true;
                pool_options = pool_options.max_connections(1).idle_timeout(None);
                connection_options.in_memory(true)
            }
        };

        let connection_pool = pool_options
            .connect_with(connection_options)
            .await?;

        Ok(Self {
            connection_pool,
            initialization_is_required,
        })
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
                registered_from_ip TEXT NOT NULL
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
        let table_names: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
            .fetch_all(&self.connection_pool)
            .await?;

        let expected_tables = ["users", "history"];

        for table in table_names {
            if !expected_tables.contains(&table.as_str()) {
                return Err(DataBaseBuildError::UnexpectedTable(table));
            }
        }
        let validation_queries = vec![
            "SELECT username, password_hash, available_tokens FROM users LIMIT 1",
            "SELECT username, timestamp, hash FROM history LIMIT 1;",
        ];

        for query in validation_queries {
            if sqlx::query(query)
                .execute(&self.connection_pool)
                .await
                .is_err()
            {
                return Err(DataBaseBuildError::Validation(query.to_string()));
            }
        }

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
                (available_tokens >= 0) AS "is_valid"
            FROM users
            "#,
        )
        .fetch(&self.connection_pool);

        while let Some(row) = rows_stream.try_next().await? {
            if !row.is_valid {
                return Err(DataBaseBuildError::ConstraintViolation(row.username));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::str::FromStr;
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use tempfile::tempdir;

    /// Helper to create a clean, fresh in-memory DB for each test.
    fn setup_memory_db() -> ServerDataBase {
        ServerDataBaseBuilder::blocking_build(DataBaseLocation::Memory)
            .expect("Failed to create in-memory database")
    }

    #[tokio::test]
    async fn test_register_and_verify_success() {
        let db = setup_memory_db();
        let user = "alice";
        let password = "SuperSecretPassword123!";
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        // Test registration.
        let reg_result = db.try_register_user(user, password, ip).await;
        assert!(reg_result.is_ok(), "Registration should succeed");

        // Test login with the correct password.
        let auth_result = db.verify_user_password(user, password).await;
        assert!(auth_result.is_ok(), "Authentication should succeed with correct password");
    }

    #[tokio::test]
    async fn test_registration_duplicate_user() {
        let db = setup_memory_db();
        let user = "bob";
        let ip = IpAddr::from_str("::1").unwrap();

        // First registration should succeed.
        db.try_register_user(user, "pass", ip).await.unwrap();

        // Trying to register the exact same user again.
        let err = db.try_register_user(user, "pass", ip).await.unwrap_err();
        assert!(
            matches!(err, RegistrationError::UserAlreadyExists(_)),
            "Expected UserAlreadyExists error"
        );
    }

    #[tokio::test]
    async fn test_verify_user_not_found_and_invalid_password() {
        let db = setup_memory_db();
        let user = "charlie";
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        // User does not exist.
        let err = db.verify_user_password("ghost", "pass").await.unwrap_err();
        assert!(
            matches!(err, AuthenticationError::UserNotFound(_)),
            "Expected UserNotFound error for non-existent user"
        );

        // Incorrect password.
        db.try_register_user(user, "correct_pass", ip).await.unwrap();
        let err = db.verify_user_password(user, "wrong_pass").await.unwrap_err();
        assert!(
            matches!(err, AuthenticationError::InvalidPassword),
            "Expected InvalidPassword error"
        );
    }

    #[tokio::test]
    async fn test_tokens_operations_success() {
        let db = setup_memory_db();
        let user = "dave";
        let ip = IpAddr::from_str("::1").unwrap();

        db.try_register_user(user, "pass", ip).await.unwrap();

        // Initial check: tokens should be 0.
        let tokens = db.get_user_tokens(user).await.unwrap();
        assert_eq!(tokens, 0, "Initial tokens should be 0");

        // Add 50 tokens.
        let tokens = db.add_user_tokens(user, 50).await.unwrap();
        assert_eq!(tokens, 50, "Tokens should be 50 after addition");

        // Subtract 20 tokens.
        let tokens = db.subtract_user_tokens(user, 20).await.unwrap();
        assert_eq!(tokens, 30, "Tokens should be 30 after subtraction");
    }

    #[tokio::test]
    async fn test_tokens_subtraction_insufficient() {
        let db = setup_memory_db();
        let user = "eve";
        let ip = IpAddr::from_str("127.127.120.2").unwrap();

        db.try_register_user(user, "pass", ip).await.unwrap();

        db.add_user_tokens(user, 10).await.unwrap();

        // Try to subtract 15 tokens when the user only has 10.
        let err = db.subtract_user_tokens(user, 15).await.unwrap_err();
        assert!(
            matches!(err, SubtractTokensError::InsufficientTokens),
            "Expected InsufficientTokens error"
        );
    }

    #[tokio::test]
    async fn test_tokens_user_not_found() {
        let db = setup_memory_db();

        let err_get = db.get_user_tokens("ghost").await.unwrap_err();
        assert!(matches!(err_get, GetTokensError::UserDoesNotExist));

        let err_add = db.add_user_tokens("ghost", 10).await.unwrap_err();
        assert!(matches!(err_add, AddTokensError::UserDoesNotExist));

        let err_sub = db.subtract_user_tokens("ghost", 10).await.unwrap_err();
        assert!(matches!(err_sub, SubtractTokensError::UserDoesNotExist));
    }

    // ==========================================
    // 2. DISK INTEGRITY AND VALIDATION TESTS
    // ==========================================

    #[tokio::test]
    async fn test_disk_db_creation_and_reload() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        // 1. Initial creation (should trigger initialize_db).
        {
            let db = ServerDataBaseBuilder::blocking_build(DataBaseLocation::Disk(db_path.clone()))
                .expect("Failed to create database on disk");

            let ip = Ipv6Addr::new(65000, 65002, 65006, 65008, 65010, 64999, 65100, 65101);

            // Insert data to verify persistence.
            db.try_register_user("frank", "pass", IpAddr::from(ip)).await.unwrap();
        } // `db` goes out of scope here, safely closing the pool.

        // 2. Reloading (should trigger validate).
        {
            let db2 = ServerDataBaseBuilder::blocking_build(DataBaseLocation::Disk(db_path))
                .expect("Failed to reload existing database");

            // Verify the user still exists.
            let tokens = db2.get_user_tokens("frank").await.unwrap();
            assert_eq!(tokens, 0);
        }
    }

    #[tokio::test]
    async fn test_validation_constraint_violation() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("corrupted.db");

        // No constraint.
        let opts = SqliteConnectOptions::new().filename(&db_path).create_if_missing(true);
        let pool = SqlitePoolOptions::new().connect_with(opts).await.unwrap();

        sqlx::query(
            r#"
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                available_tokens INTEGER NOT NULL,
                registered_from_ip TEXT NOT NULL
            );
            CREATE TABLE history (
                username TEXT NOT NULL, timestamp INTEGER NOT NULL, hash TEXT NOT NULL,
                PRIMARY KEY (username, timestamp)
            );
            "#
        ).execute(&pool).await.unwrap();

        // Inject the wrong value.
        sqlx::query("INSERT INTO users (username, password_hash, available_tokens, registered_from_ip) VALUES ('hacker', 'hash', -5, '127.0.0.1')")
            .execute(&pool)
            .await
            .unwrap();

        pool.close().await;

        // Now it should correctly identify a broken database.
        let err = ServerDataBaseBuilder::blocking_build(DataBaseLocation::Disk(db_path))
            .unwrap_err();

        assert!(
            matches!(err, DataBaseBuildError::ConstraintViolation(name) if name == "hacker"),
            "Expected ConstraintViolation for user 'hacker'"
        );
    }

    #[tokio::test]
    async fn test_validation_missing_table() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("bogus.db");

        // Create an empty DB manually without the required tables.
        let opts = SqliteConnectOptions::new().filename(&db_path).create_if_missing(true);
        let pool = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
        pool.close().await;

        // Trying to load it will fail on the validation queries.
        let err = ServerDataBaseBuilder::blocking_build(DataBaseLocation::Disk(db_path))
            .unwrap_err();

        assert!(
            matches!(err, DataBaseBuildError::Validation(_)),
            "Expected Validation error due to missing tables"
        );
    }

    #[tokio::test]
    async fn test_validation_with_extra_tables_fails() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("strict.db");

        // Create a valid DB.
        let _ = ServerDataBaseBuilder::blocking_build(DataBaseLocation::Disk(db_path.clone())).unwrap();

        // Inject an unexpected table.
        let opts = SqliteConnectOptions::new().filename(&db_path);
        let pool = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
        sqlx::query("CREATE TABLE secret_backdoor (id INTEGER)")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        // Reloading the DB MUST fail because of strict table checking.
        let err = ServerDataBaseBuilder::blocking_build(DataBaseLocation::Disk(db_path))
            .unwrap_err();

        assert!(
            matches!(err, DataBaseBuildError::UnexpectedTable(name) if name == "secret_backdoor"),
            "The DB should have rejected the unexpected table!"
        );
    }
}
