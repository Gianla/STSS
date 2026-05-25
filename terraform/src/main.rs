//! Main user of terraform::lib.rs, as well as a simple wrapper around it.

use clap::Parser;
use std::io::{self, Write, Error};
use std::path::PathBuf;

use terraform::{AnyServerFiles, EnvironmentGeneratorBuilder, Generator};

/// Wrapper to craft error easily.
fn main_error(msg: impl AsRef<str>) -> io::Result<()> {
    Err( Error::other(msg.as_ref()) )
}

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

fn main() -> io::Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();

    let mut stdout = io::stdout().lock();

    writeln!(stdout, "Initializing the environment in directory: {:?}", cli.root)?;

    // 1. Build the EnvironmentGenerator
    let mut env_builder = EnvironmentGeneratorBuilder::from_simulation_dir(&cli.root);

    if let Some(c) = cli.client_dir {
        match c.try_into() {
            Ok(valid_name) => {
                env_builder.with_client_dir(valid_name);
            }
            Err(e) => {
                return main_error(format!("Invalid client directory name provided: {}", e));
            }
        }
    }

    if let Some(s) = cli.server_dir {
        match s.try_into() {
            Ok(valid_name) => {
                env_builder.with_server_dir(valid_name);
            }
            Err(e) => {
                return main_error(format!("Invalid server directory name provided: {}", e));
            }
        }
    }

    if let Some(ca) = cli.ca_dir {
        match ca.try_into() {
            Ok(valid_name) => {
                env_builder.with_ca_dir(valid_name);
            }
            Err(e) => {
                return main_error(format!("Invalid CA directory name provided: {}", e));
            }
        }
    }

    let env = match env_builder.build() {
        Ok(e) => e,
        Err(e) => {
            return main_error(format!("Error creating directories: {}", e));
        }
    };

    // 2. Build the prefixes for the files
    let server_files = match AnyServerFiles::default(cli.server_prefix.as_str()) {
        Ok(f) => f,
        Err(e) => {
            return main_error(format!("Invalid server prefix: {}", e));
        }
    };

    let ca_files = match AnyServerFiles::default(cli.ca_prefix.as_str()) {
        Ok(f) => f,
        Err(e) => {
            return main_error(format!("Invalid CA prefix: {}", e));
        }
    };

    // 3. Instantiate the generator and start the process
    let generator = match Generator::new_from_files(server_files, ca_files, env) {
        Ok(g) => g,
        Err(e) => {
            return main_error(format!("Failed to initialize the generator: {}", e));
        }
    };

    writeln!(stdout, "Generating keys, certificates, and configuration files...")?;

    match generator.generate_all() {
        Ok(_) => {
            writeln!(stdout, "Environment generated successfully!")?;
            Ok(())
        }
        Err(e) => {
            main_error(format!("Fatal error during generation: {}", e))
        }
    }
}
