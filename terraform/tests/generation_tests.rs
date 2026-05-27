//! Tests for the EnvironmentGenerator and EnvironmentGeneratorBuilder of terraform.

use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;
use terraform::*;

#[test]
fn test_environments_are_always_under_root() {
    let root_path = PathBuf::from("/virtual/root/sim");
    let env = EnvironmentGeneratorBuilder::build_default(&root_path);

    assert!(
        env.client_dir().starts_with(&root_path),
        "Client dir is not under root"
    );
    assert!(
        env.server_dir().starts_with(&root_path),
        "Server dir is not under root"
    );
    assert!(
        env.ca_dir().starts_with(&root_path),
        "CA dir is not under root"
    );
}

#[test]
fn test_builder_fails_on_duplicate_environments() {
    let root_path = PathBuf::from("sim_root");
    let mut builder = EnvironmentGeneratorBuilder::from_simulation_dir(root_path);

    builder.with_client_dir(
        "same_name"
            .try_into()
            .expect("this hardcoded value shouldn't fail"),
    );
    builder.with_server_dir(
        "same_name"
            .try_into()
            .expect("this hardcoded value shouldn't fail"),
    );

    let result = builder.build();
    assert!(
        matches!(
            result,
            Err(EnvironmentGeneratorBuildError::FoldersMustBeDifferent)
        ),
        "builder should've failed because of equal folders"
    );
}

#[test]
fn test_fails_if_root_directory_already_exists() {
    let temp_base = tempdir().expect("cannot create tempdir");

    let root_path = temp_base.path().join("existing_sim_root");
    fs::create_dir(&root_path).expect("cannot create simulated root");

    let env = EnvironmentGeneratorBuilder::build_default(&root_path);
    let server_files = AnyServerFiles::default("server_").unwrap();
    let ca_files = AnyServerFiles::default("ca_").unwrap();
    let client_files =  ClientFiles::default("im_non_existent.tetext").unwrap();

    let generator = Generator::new_from_files(server_files, ca_files, client_files, env).unwrap();
    let result = generator.generate_all();

    assert!(
        result.is_err(),
        "generator should've fail, directory already existed"
    );

    if let Err(GenerationError::KeyGen(KeyGenError::Io(_, err))) = result {
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::AlreadyExists,
            "error should have been AlreadyExists"
        );
    } else {
        panic!("generator gave an unknown error: {:?}", result);
    }
}

#[test]
fn test_successful_generation_from_scratch() {
    let temp_base = tempdir().expect("cannot create tempdir");

    let root_path = temp_base.path().join("new_simulation_root");

    let env = EnvironmentGeneratorBuilder::build_default(&root_path);
    let server_files = AnyServerFiles::default("server_").unwrap();
    let ca_files = AnyServerFiles::default("ca_").unwrap();
    let client_files = ClientFiles::default("config.toml").unwrap();

    let generator = Generator::new_from_files(server_files, ca_files, client_files, env).unwrap();

    assert!(
        generator.generate_all().is_ok(),
        "generation failed from clean environment"
    );

    assert!(root_path.exists(), "root wasn't created");
    assert!(root_path.join(DEFAULT_CLIENT_ENV_SUBDIR).exists());
    assert!(root_path.join(DEFAULT_SERVER_ENV_SUBDIR).exists());
    assert!(root_path.join(DEFAULT_CA_ENV_SUBDIR).exists());

    let client_dir = root_path.join(DEFAULT_CLIENT_ENV_SUBDIR);
    assert!(client_dir.join("ca_tls_certificate.pem").exists());
    assert!(client_dir.join("server_rsa_pub_key.pem").exists());
    assert!(client_dir.join("config.toml").exists());

    let server_dir = root_path.join(DEFAULT_SERVER_ENV_SUBDIR);
    assert!(server_dir.join("server_tls_private_key.pem").exists());
    assert!(server_dir.join("server_tls_certificate.pem").exists());
    assert!(server_dir.join("server_rsa_priv_key.pem").exists());
    assert!(server_dir.join("ca_tls_certificate.pem").exists());
    assert!(server_dir.join("server_config.toml").exists());

    let ca_dir = root_path.join(DEFAULT_CA_ENV_SUBDIR);
    assert!(ca_dir.join("ca_tls_certificate.pem").exists());
    assert!(ca_dir.join("ca_tls_private_key.pem").exists());

}

#[test]
fn test_generator_fails_with_equal_prefixes() {
    let root_path = PathBuf::from("dummy_root");
    let env = EnvironmentGeneratorBuilder::build_default(&root_path);

    let same_prefix = "same_prefix_";
    let server_files = AnyServerFiles::default(same_prefix).unwrap();
    let ca_files = AnyServerFiles::default(same_prefix).unwrap();
    let client_files =  ClientFiles::default("config.toml").unwrap();

    let result = Generator::new_from_files(server_files, ca_files, client_files, env);

    assert!(
        matches!(result, Err(GeneratorCreationError::EqualPrefixes)),
        "generator should've failed because prefixes were the same"
    );
}
