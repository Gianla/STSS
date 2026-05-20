//! Main user of terraform::lib.rs, as well as a simple wrapper around it.

use clap::Parser;
use std::path::PathBuf;
use std::process;

use terraform::{AnyServerFiles, EnvironmentGeneratorBuilder, Generator};

/// CLI tool to bootstrap the TSA Project simulation environment
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The mandatory root directory where the environment will be generated
    root: PathBuf,

    /// Optional specific name for the client directory
    #[arg(long)]
    client_dir: Option<String>,

    /// Optional specific name for the server directory
    #[arg(long)]
    server_dir: Option<String>,

    /// Optional specific name for the CA directory
    #[arg(long)]
    ca_dir: Option<String>,

    /// Prefix for the server generated files
    #[arg(long, default_value = "server_")]
    server_prefix: String,

    /// Prefix for the CA generated files
    #[arg(long, default_value = "ca_")]
    ca_prefix: String,
}

fn main() {
    // Parse command line arguments
    let cli = Cli::parse();

    println!("Initializing the environment in directory: {:?}", cli.root);

    // 1. Build the EnvironmentGenerator
    let mut env_builder = EnvironmentGeneratorBuilder::from_simulation_dir(&cli.root);

    if let Some(c) = cli.client_dir {
        match c.try_into() {
            Ok(valid_name) => {
                env_builder.with_client_dir(valid_name);
            }
            Err(e) => {
                eprintln!("Invalid client directory name provided: {}", e);
                process::exit(1);
            }
        }
    }

    if let Some(s) = cli.server_dir {
        match s.try_into() {
            Ok(valid_name) => {
                env_builder.with_server_dir(valid_name);
            }
            Err(e) => {
                eprintln!("Invalid server directory name provided: {}", e);
                process::exit(1);
            }
        }
    }

    if let Some(ca) = cli.ca_dir {
        match ca.try_into() {
            Ok(valid_name) => {
                env_builder.with_ca_dir(valid_name);
            }
            Err(e) => {
                eprintln!("Invalid CA directory name provided: {}", e);
                process::exit(1);
            }
        }
    }

    let env = match env_builder.build() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error creating directories: {}", e);
            process::exit(1);
        }
    };

    // 2. Build the prefixes for the files
    let server_files = match AnyServerFiles::default(cli.server_prefix.as_str()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Invalid server prefix: {}", e);
            process::exit(1);
        }
    };

    let ca_files = match AnyServerFiles::default(cli.ca_prefix.as_str()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Invalid CA prefix: {}", e);
            process::exit(1);
        }
    };

    // 3. Instantiate the generator and start the process
    let generator = match Generator::new_from_files(server_files, ca_files, env) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Failed to initialize the generator: {}", e);
            process::exit(1);
        }
    };

    println!("Generating keys, certificates, and configuration files...");

    match generator.generate_all() {
        Ok(_) => {
            println!("Environment generated successfully!");
        }
        Err(e) => {
            eprintln!("Fatal error during generation: {}", e);
            process::exit(1);
        }
    }
}
