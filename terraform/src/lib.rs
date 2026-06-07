//! Useful to set up a simulated environment where client, server and CA can communicate between
//! each other.

use client_cli::config::Config as ClientConfig;
use const_format::concatcp;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ED25519};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use server::config::{
    Config as ServerConfig, KeysConfig, NetworkConfig, RuntimeConfig, SyncedTimeOracleConfig,
};
use std::collections::HashSet;
use std::convert::Into;
use std::fmt::Formatter;
use std::num::NonZero;
use std::path::{Component, Path, PathBuf};
use std::{fmt, fs, io};
use thiserror::Error;

/// Abstracts a String into a filesystem name, which can be a file or the name of a single
/// directory. This is useful when working with directories and files,
/// ensuring that the user is passing a properly formatted filename and not a complex directory
/// path that could also lead to vulnerabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSystemName(String);

/// Errors that might arise while creating a FileName.
#[derive(Error, Debug)]
pub enum FileSystemNameError {
    #[error("{0:?} is not a valid file name")]
    InvalidFileName(String),
}

impl FileSystemName {
    /// Checks if the name is valid and returns a FileSystemName.
    /// Good examples:
    ///     FileSystemName::new("my_new_file") => ok!
    ///     FileSystemName::new("my_file.txt") => ok!
    ///     FileSystemName::new("my_already_existing_file") => ok!
    ///     FileSystemName::new("some_name_of_directory") => ok!
    /// Fail examples:
    ///     FileSystemName::new("dir/my_file.txt") => error!
    ///     FileSystemName::new("../escape") => error!
    ///     FileSystemName::new(".") => error!
    pub fn new(name: impl AsRef<str>) -> Result<Self, FileSystemNameError> {
        let name_ref = name.as_ref();
        let path = Path::new(name_ref);

        // dismember the path into its components.
        let mut components = path.components();

        // this recursive struct can be dismantled into multiple cases: being correct while
        // borrowing other data, being correct while not borrowing other data, being incorrect.
        // The first element of this struct falls into the first case if it is a complex
        // directory path: we don't want that, so we return an error. We consider it to be correct
        // iff it is a simple component, that is, only a filename.
        match (components.next(), components.next()) {
            (Some(Component::Normal(_)), None) => Ok(Self(name_ref.to_string())),
            _ => Err(FileSystemNameError::InvalidFileName(name_ref.to_string())),
        }
    }

    /// Concatenates this FileSystemName with another FileSystemName.
    /// Since both are already guaranteed to be valid filenames without path separators,
    /// their concatenation is intrinsically valid. Thus, we can safely bypass
    /// the validation checks and return a new FileSystemName directly.
    pub fn concat(&self, suffix: &FileSystemName) -> Self {
        Self(format!("{}{}", self.0, suffix.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// needed for join().
impl AsRef<Path> for FileSystemName {
    fn as_ref(&self) -> &Path {
        Path::new(&self.0)
    }
}

// needed for errors.
impl fmt::Display for FileSystemName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// implement try_from and try_into also for strings.
impl TryFrom<&str> for FileSystemName {
    type Error = FileSystemNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for FileSystemName {
    type Error = FileSystemNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

pub const DEFAULT_CLIENT_ENV_SUBDIR: &str = "client_env";
pub const DEFAULT_SERVER_ENV_SUBDIR: &str = "server_env";
pub const DEFAULT_CA_ENV_SUBDIR: &str = "ca_env";
pub const DEFAULT_SERVER_IP_STR: &str = "127.0.0.1";
pub const DEFAULT_SERVER_IP_PORT: u16 = 8080;
pub const DEFAULT_CA_IP_PORT: u16 = 8081;

/// Groups the folders for the three actors.
pub struct EnvironmentGenerator {
    client_dir: PathBuf,
    server_dir: PathBuf,
    ca_dir: PathBuf,
    root_dir: PathBuf,
}

impl EnvironmentGenerator {
    /// Returns a new EnvironmentGenerator. No fancy abstraction or flexibility is provided since
    /// this method is intended for internal use (after all, it's not pub). Furthermore, the builder
    /// will check and convert everything into PathBuf itself, effectively being the official
    /// interface of this struct.
    fn internal_new(
        client_dir: PathBuf,
        server_dir: PathBuf,
        ca_dir: PathBuf,
        root: PathBuf,
    ) -> Self {
        Self {
            client_dir,
            server_dir,
            ca_dir,
            root_dir: root,
        }
    }
    pub fn client_dir(&self) -> &Path {
        &self.client_dir
    }

    pub fn server_dir(&self) -> &Path {
        &self.server_dir
    }

    pub fn ca_dir(&self) -> &Path {
        &self.ca_dir
    }

    pub fn root(&self) -> &Path {
        &self.root_dir
    }
}

/// Builder for EnvironmentGenerator.
pub struct EnvironmentGeneratorBuilder {
    client_dir: Option<FileSystemName>,
    server_dir: Option<FileSystemName>,
    ca_dir: Option<FileSystemName>,
    root_dir: PathBuf,
}

/// Errors that might arise while building an environment.
#[derive(Error, Debug)]
pub enum EnvironmentGeneratorBuildError {
    #[error("two or more given folders are equal: all of them should be different")]
    FoldersMustBeDifferent,
}

impl EnvironmentGeneratorBuilder {
    pub fn from_simulation_dir(simulation_dir: impl Into<PathBuf>) -> Self {
        let root = simulation_dir.into();
        Self {
            client_dir: None,
            server_dir: None,
            ca_dir: None,
            root_dir: root,
        }
    }

    pub fn with_client_dir(&mut self, client_dir: FileSystemName) -> &mut Self {
        self.client_dir = Some(client_dir);
        self
    }

    pub fn with_server_dir(&mut self, server_dir: FileSystemName) -> &mut Self {
        self.server_dir = Some(server_dir);
        self
    }

    pub fn with_ca_dir(&mut self, ca_dir: FileSystemName) -> &mut Self {
        self.ca_dir = Some(ca_dir);
        self
    }

    pub fn build(self) -> Result<EnvironmentGenerator, EnvironmentGeneratorBuildError> {
        let client_path = self.root_dir.join(self.client_dir.unwrap_or_else(|| {
            FileSystemName::new(DEFAULT_CLIENT_ENV_SUBDIR).expect(concatcp!(
                "\"",
                DEFAULT_CLIENT_ENV_SUBDIR,
                "\" should be convertible into FileSystemName \
                    because it's const"
            ))
        }));
        let server_path = self.root_dir.join(self.server_dir.unwrap_or_else(|| {
            FileSystemName::new(DEFAULT_SERVER_ENV_SUBDIR).expect(concatcp!(
                "\"",
                DEFAULT_SERVER_ENV_SUBDIR,
                "\" should be convertible into FileSystemName \
                    because it's const"
            ))
        }));
        let ca_path = self.root_dir.join(self.ca_dir.unwrap_or_else(|| {
            FileSystemName::new(DEFAULT_CA_ENV_SUBDIR).expect(concatcp!(
                "\"",
                DEFAULT_CA_ENV_SUBDIR,
                "\" should be convertible into FileSystemName \
                    because it's const"
            ))
        }));

        let mut seen = HashSet::new();

        let has_duplicates = [&client_path, &server_path, &ca_path]
            .into_iter()
            .any(|path| !seen.insert(path));

        if has_duplicates {
            return Err(EnvironmentGeneratorBuildError::FoldersMustBeDifferent);
        }

        Ok(EnvironmentGenerator::internal_new(
            client_path,
            server_path,
            ca_path,
            self.root_dir,
        ))
    }

    pub fn build_default(path: impl Into<PathBuf>) -> EnvironmentGenerator {
        Self::from_simulation_dir(path.into())
            .build()
            .expect("default values shouldn't fail")
    }
}

pub struct AnyServerFiles {
    /// Server's TLS certificate.
    tls_cert_name: FileSystemName,
    /// Server's private TLS key.
    tls_key_name: FileSystemName,

    /// Server's public RSA key.
    sign_pub_key_name: FileSystemName,
    /// Server's private RSA key.
    sign_priv_key_name: FileSystemName,

    /// Server's configuration file.
    toml_name: FileSystemName,

    /// Given prefix.
    _given_prefix: FileSystemName,
}

impl AnyServerFiles {
    fn internal_new(
        tls_cert_name: FileSystemName,
        tls_key_name: FileSystemName,
        sign_pub_key_name: FileSystemName,
        sign_priv_key_name: FileSystemName,
        toml_name: FileSystemName,
        _given_prefix: FileSystemName,
    ) -> Self {
        Self {
            tls_cert_name,
            tls_key_name,
            sign_pub_key_name,
            sign_priv_key_name,
            toml_name,
            _given_prefix,
        }
    }

    pub fn default(
        prefix: impl TryInto<FileSystemName, Error = FileSystemNameError>,
    ) -> Result<Self, FileSystemNameError> {
        let safe_prefix = prefix.try_into()?;

        let res = Self::internal_new(
            safe_prefix.concat(
                &FileSystemName::new("tls_certificate.pem")
                    .expect("this hardcoded value shouldn't fail"),
            ),
            safe_prefix.concat(
                &FileSystemName::new("tls_private_key.pem")
                    .expect("this hardcoded value shouldn't fail"),
            ),
            safe_prefix.concat(
                &FileSystemName::new("rsa_pub_key.pem")
                    .expect("this hardcoded value shouldn't fail"),
            ),
            safe_prefix.concat(
                &FileSystemName::new("rsa_priv_key.pem")
                    .expect("this hardcoded value shouldn't fail"),
            ),
            safe_prefix.concat(
                &FileSystemName::new("config.toml").expect("this hardcoded value shouldn't fail"),
            ),
            safe_prefix,
        );

        Ok(res)
    }
}

pub struct ClientFiles {
    toml_file: FileSystemName,
}

impl ClientFiles {
    pub fn new(toml_file: impl Into<FileSystemName>) -> Self {
        Self {
            toml_file: toml_file.into(),
        }
    }

    pub fn default<T>(toml_file: T) -> Result<Self, T::Error>
    where
        T: TryInto<FileSystemName>,
    {
        let file = toml_file.try_into()?;
        Ok(Self { toml_file: file })
    }
}

/// Heuristic to decide whether to include cryptographic threads or not. In general, for
/// systems that supports hardware acceleration, we decide not to include them since
/// cryptographical operations won't take long (and, so, a separated thread).
/// Otherwise, we reserve some threads for specific signing operations so that the server
/// will keep going with connections.
pub fn heuristic_working_threads(thread_limits: Option<(usize, usize)>) -> (bool, usize) {
    // for some unknown reasons, macOS is the only operating system pretending to put std::arch::
    // as a prefix before every feature detection. Thank you, macOS, for being the incredible,
    // beautiful operating system that you pretend to be but aren't.
    #[cfg(target_arch = "x86_64")]
    // both adx and bmi2 are instruction sets that deals well with big numbers operations, so
    // we can say that RSA is handled well.
    let is_crypto_hardware_accelerated = !(!std::arch::is_x86_feature_detected!("adx")
        && !std::arch::is_x86_feature_detected!("adx")
        && !std::arch::is_x86_feature_detected!("bmi2"));

    #[cfg(target_arch = "aarch64")]
    // neon is quite always compatible with hardware acceleration. Otherwise, aes might
    // be available too.
    let is_crypto_hardware_accelerated = std::arch::is_aarch64_feature_detected!("neon")
        || std::arch::is_aarch64_feature_detected!("aes");

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    // fallback scenario for unsupported architectures.
    let is_crypto_hardware_accelerated = false;

    // heuristic to decide the number of threads to be used. We divide the available number
    // by 4, which should be more than enough for 4-threads architectures and more.
    // Furthermore, we establish a minimum of 16 in order to avoid syscall poisoning and
    // be ultra-safe regarding performance DoS.
    const MIN_THREADS: usize = 2;
    const MAX_THREADS: usize = 16;

    let (min, max) = match thread_limits {
        Some((min, max)) => {
            if min > max {
                (max, min)
            } else {
                (min, max)
            }
        }
        None => (MIN_THREADS, MAX_THREADS),
    };

    let base_threads = std::thread::available_parallelism()
        .map(|n| n.get() / 4)
        .unwrap_or(MIN_THREADS); // todo: add a warning

    (is_crypto_hardware_accelerated, base_threads.clamp(min, max))
}

/// Errors that might arise while generating the keys.
#[derive(Error, Debug)]
pub enum KeyGenError {
    #[error("I/O error while writing {0:?}: {1}")]
    Io(String, io::Error),

    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("RSA error: {0}")]
    RsaPkcs8(#[from] rsa::pkcs8::Error),

    #[error("TLS certificate Error: {0}")]
    Tls(#[from] rcgen::Error),

    #[error("RSA PEM encoding error: {0}")]
    Pem(#[from] rsa::pkcs8::spki::Error),

    #[error("error while generating the CA certificates: {0:?}")]
    CACertificateCreation(String),

    #[error("error while generating the server certificates: {0:?}")]
    ServerCertificateCreation(String),
}

/// Errors that might arise while generating the toml.
#[derive(Error, Debug)]
pub enum TomlGenError {
    #[error("I/O Error while writing {0:?}: {1}")]
    Io(String, std::io::Error),

    #[error(
        "Error while getting the absolute path of {0:?}: {1:?}, probably, the toml generation \
         function has been called before the files it refers to"
    )]
    Canonicalize(String, std::io::Error),

    #[error("invalid path {0:?}, please use a standard utf-8 format")]
    InvalidUtf8Path(String),

    #[error("error while converting the default configs into toml: {0:?}")]
    TomlGeneration(String),

    #[error("error while writing the toml to file: {0:?}")]
    CannotWriteToFile(String),

    #[error(
        "incoherent thread limits: they should be strictly increasing while {0} and {1}, where \
         {0} >= {1} has been given"
    )]
    IncoherentThreadLimits(usize, usize),
}

/// Groups up key and toml generation error(s).
#[derive(Error, Debug)]
pub enum GenerationError {
    #[error(transparent)]
    KeyGen(#[from] KeyGenError),

    #[error(transparent)]
    TomlGen(#[from] TomlGenError),
}

/// Groups up key and toml generation error(s).
#[derive(Error, Debug)]
pub enum GeneratorCreationError {
    #[error("cannot create a generator with two equal prefixes")]
    EqualPrefixes,
}

/// Used to generate defaults when terraform is required to do so. A struct is needed in order
/// to maintain coherence between the paths and for future extendibility (OCP).
pub struct Generator {
    server_files: AnyServerFiles,
    ca_files: AnyServerFiles,
    client_files: ClientFiles,
    env: EnvironmentGenerator,
}

impl Generator {
    pub fn new_from_files(
        server_files: AnyServerFiles,
        ca_files: AnyServerFiles,
        client_files: ClientFiles,
        env: EnvironmentGenerator,
    ) -> Result<Self, GeneratorCreationError> {
        if server_files._given_prefix == ca_files._given_prefix {
            return Err(GeneratorCreationError::EqualPrefixes);
        }

        Ok(Self {
            server_files,
            ca_files,
            client_files,
            env,
        })
    }

    pub fn generate_all(&self) -> Result<(), GenerationError> {
        self.generate_keys_and_distribute()?;
        self.generate_tomls()?;

        Ok(())
    }

    /// Wrapper to generate both the server toml and the CA toml.
    fn generate_tomls(&self) -> Result<(), TomlGenError> {
        self.generate_server_toml(None)?;
        self.generate_client_toml()?;
        self.generate_ca_toml()?;

        Ok(())
    }

    /// Generates all cryptographic keys and certificates, and writes them to the
    /// appropriate folders specified in the EnvironmentGenerator.
    fn generate_keys_and_distribute(&self) -> Result<(), KeyGenError> {
        let mut rng = rand::rng();
        // 1. CA's environment generation.

        // generate CA KeyPair for signing certificates.
        let ca_keypair = KeyPair::generate_for(&PKCS_ED25519).map_err(KeyGenError::Tls)?;
        let ca_key_pem = ca_keypair.serialize_pem();

        // create CA Certificate Params.
        let mut ca_params = CertificateParams::new(vec!["Root CA".to_string()])
            .map_err(|e| KeyGenError::CACertificateCreation(e.to_string()))?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "University of Pisa");

        ca_params
            .distinguished_name
            .push(DnType::CommonName, "CyberSecurity Project");

        // create the self-signed CA certificate.
        let ca_cert = ca_params
            .self_signed(&ca_keypair)
            .map_err(|e| KeyGenError::CACertificateCreation(e.to_string()))?;

        let ca_cert_pem = ca_cert.pem();

        // create the issuer: this is useful to already-sign the server.
        let ca_issuer = rcgen::Issuer::new(ca_params, &ca_keypair);

        // 2. Server TLS generation.

        // Generate Server TLS KeyPair.
        let server_tls_keypair = KeyPair::generate_for(&PKCS_ED25519).map_err(KeyGenError::Tls)?;

        let server_tls_key_pem = server_tls_keypair.serialize_pem();

        // create the server's Certificate Params.
        let mut server_tls_params = CertificateParams::new(vec![DEFAULT_SERVER_IP_STR.to_string()])
            .map_err(|e| KeyGenError::CACertificateCreation(e.to_string()))?;

        server_tls_params
            .distinguished_name
            .push(DnType::OrganizationName, "University of Pisa");

        server_tls_params
            .distinguished_name
            .push(DnType::CommonName, "TSA Server");

        // create the Server certificate and SIGN IT WITH THE CA.
        let server_tls_cert = server_tls_params
            .signed_by(&server_tls_keypair, &ca_issuer)
            .map_err(|e| KeyGenError::ServerCertificateCreation(e.to_string()))?;

        let server_tls_cert_pem = server_tls_cert.pem();

        // 3. Server TSA generation.

        // generate RSA keys for Timestamp Authority signing
        let server_rsa_priv = RsaPrivateKey::new(&mut rng, 2048).map_err(KeyGenError::Rsa)?;
        let server_rsa_pub = RsaPublicKey::from(&server_rsa_priv);

        let server_rsa_priv_pem = server_rsa_priv
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(KeyGenError::RsaPkcs8)?;
        let server_rsa_pub_pem = server_rsa_pub
            .to_public_key_pem(LineEnding::LF)
            .map_err(KeyGenError::from)?;

        // 4. File distribution.

        // create the simulation directory.
        fs::create_dir(&self.env.root_dir)
            .map_err(|e| KeyGenError::Io(self.env.root_dir.to_string_lossy().to_string(), e))?;

        // ensure directories exist.
        fs::create_dir(&self.env.ca_dir)
            .map_err(|e| KeyGenError::Io(self.env.ca_dir.to_string_lossy().to_string(), e))?;
        fs::create_dir(&self.env.server_dir)
            .map_err(|e| KeyGenError::Io(self.env.server_dir.to_string_lossy().to_string(), e))?;
        fs::create_dir(&self.env.client_dir)
            .map_err(|e| KeyGenError::Io(self.env.client_dir.to_string_lossy().to_string(), e))?;

        // helper closure to write strings to files cleanly.
        let write_file =
            |dir: &Path, filename: &FileSystemName, content: &str| -> Result<(), KeyGenError> {
                let path = dir.join(filename);
                fs::write(&path, content)
                    .map_err(|e| KeyGenError::Io(path.to_string_lossy().to_string(), e))
            };

        // --- CA ENVIRONMENT ---
        // CA needs its own private key and its self-signed cert
        write_file(&self.env.ca_dir, &self.ca_files.tls_key_name, &ca_key_pem)?;
        write_file(&self.env.ca_dir, &self.ca_files.tls_cert_name, &ca_cert_pem)?;

        // --- SERVER ENVIRONMENT ---
        // Server needs its TLS private key, its TLS cert (signed by CA), and its RSA private key.
        // Furthermore, if it needs to refresh its certificates, it needs the tls certificate
        // of the CA.
        write_file(
            &self.env.server_dir,
            &self.server_files.tls_key_name,
            &server_tls_key_pem,
        )?;
        write_file(
            &self.env.server_dir,
            &self.server_files.tls_cert_name,
            &server_tls_cert_pem,
        )?;
        write_file(
            &self.env.server_dir,
            &self.server_files.sign_priv_key_name,
            server_rsa_priv_pem.as_str(),
        )?;
        write_file(
            &self.env.server_dir,
            &self.ca_files.tls_cert_name,
            &ca_cert_pem,
        )?;

        // --- CLIENT ENVIRONMENT ---
        // Client needs the CA cert (to verify TLS) and the Server RSA Pub Key (to verify Timestamps).
        write_file(
            &self.env.client_dir,
            &self.ca_files.tls_cert_name,
            &ca_cert_pem,
        )?;
        write_file(
            &self.env.client_dir,
            &self.server_files.sign_pub_key_name,
            server_rsa_pub_pem.as_str(),
        )?;

        Ok(())
    }

    fn get_canonical_path(&self, dir: &Path, file_name: &str) -> Result<PathBuf, TomlGenError> {
        dir.join(file_name)
            .canonicalize()
            .map_err(|e| TomlGenError::Canonicalize(file_name.to_string(), e))
    }

    /// Uses the paths to generate the default toml.
    /// thread_limits refers to the two numbers in which the heuristic have to stay in:
    /// if it calculates a number outside of this range, the result will fall to one of the two
    /// edges anyway. If no limits are given, the result is clamped inside a reasonable amount of
    /// threads.
    fn generate_server_toml(
        &self,
        thread_limits: Option<(usize, usize)>,
    ) -> Result<(), TomlGenError> {
        let (is_crypto_hardware_accelerated, n_threads) = heuristic_working_threads(thread_limits);

        let tls_cert_path = self.get_canonical_path(
            self.env.server_dir(),
            self.server_files.tls_cert_name.as_str(),
        )?;
        let tls_priv_path = self.get_canonical_path(
            self.env.server_dir(),
            self.server_files.tls_key_name.as_str(),
        )?;
        let tss_priv_path = self.get_canonical_path(
            self.env.server_dir(),
            self.server_files.sign_priv_key_name.as_str(),
        )?;
        let ca_cert_path =
            self.get_canonical_path(self.env.server_dir(), self.ca_files.tls_cert_name.as_str())?;

        let default_synced_time_oracle = SyncedTimeOracleConfig::new(
            "pool.ntp.org".to_string(),
            123,
            "0.0.0.0".to_string(),
            0,
            5,
        );

        let default = ServerConfig::new(
            NetworkConfig::new(String::from(DEFAULT_SERVER_IP_STR), DEFAULT_SERVER_IP_PORT),
            RuntimeConfig::new(
                n_threads,
                if is_crypto_hardware_accelerated { 0 } else { 1 },
            ),
            KeysConfig::new(tls_cert_path, tls_priv_path, tss_priv_path, ca_cert_path),
            Some(default_synced_time_oracle),
            None,
            None,
        );

        let toml_default = toml::to_string_pretty(&default)
            .map_err(|e| TomlGenError::TomlGeneration(e.to_string()))?;

        let final_path = self.env.server_dir.join(&self.server_files.toml_name);

        fs::write(&final_path, toml_default)
            .map_err(|e| TomlGenError::Io(final_path.to_string_lossy().to_string(), e))
    }

    fn generate_client_toml(&self) -> Result<(), TomlGenError> {
        let default = ClientConfig::new(
            String::from(DEFAULT_SERVER_IP_STR),
            NonZero::new(DEFAULT_SERVER_IP_PORT).expect(concatcp!(
                "port is zero but this should be impossible since \"{}\" is hardcoded",
                DEFAULT_SERVER_IP_PORT
            )),
            DEFAULT_SERVER_IP_STR,
            false,
            self.get_canonical_path(self.env.client_dir(), self.ca_files.tls_cert_name.as_str())?,
            self.get_canonical_path(
                self.env.client_dir(),
                self.server_files.sign_pub_key_name.as_str(),
            )?,
        );

        let toml_default = toml::to_string_pretty(&default)
            .map_err(|e| TomlGenError::TomlGeneration(e.to_string()))?;

        let final_path = self.env.client_dir.join(&self.client_files.toml_file);

        fs::write(&final_path, toml_default)
            .map_err(|e| TomlGenError::Io(final_path.to_string_lossy().to_string(), e))
    }

    fn generate_ca_toml(&self) -> Result<(), TomlGenError> {
        let ca_cert_path =
            self.get_canonical_path(self.env.ca_dir(), self.ca_files.tls_cert_name.as_str())?;
        let ca_key_path =
            self.get_canonical_path(self.env.ca_dir(), self.ca_files.tls_key_name.as_str())?;

        let toml_default = format!(
            "[network]\nip = \"{}\"\nport = {}\n\n[keys]\nca_cert_path = \"{}\"\nca_key_path = \"{}\"\n",
            DEFAULT_SERVER_IP_STR,
            DEFAULT_CA_IP_PORT,
            ca_cert_path.display(),
            ca_key_path.display(),
        );

        let final_path = self.env.ca_dir.join(&self.ca_files.toml_name);

        fs::write(&final_path, toml_default)
            .map_err(|e| TomlGenError::Io(final_path.to_string_lossy().to_string(), e))
    }
}
