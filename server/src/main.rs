#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{ArgGroup, Parser, Subcommand};
use rcgen::DnValue;
use server::config::Config;
use server::rekey::RekeyClientManager;
use server::server::STSServer;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "STSS")]
#[command(author = "Gianluca Vizziello, Gianmarco De Laurentiis")]
#[command(version = "1.0")]
#[command(about = "Simple TimeStamp Server, or STSS, is a project for the course Foundation of \
                   Cybersecurity of the Master’s Degree in Cybersecurity, disbursed by University \
                   of Pisa.", long_about = None)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .args(["config", "rekey"])
))]
struct Cli {
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// Starts the server with a configuration file.
    Config {
        /// The path to the configuration file
        #[arg(long)]
        file: PathBuf,
    },

    /// Starts the server in rekey mode.
    Rekey {
        #[arg(long)]
        address: SocketAddr,

        #[arg(long)]
        server_ip: IpAddr,

        #[arg(long, value_parser = parse_dn_value)]
        organization_name: DnValue,

        #[arg(long, value_parser = parse_dn_value)]
        server_name: DnValue,

        #[arg(long)]
        output: PathBuf,
    },
}

fn parse_dn_value(s: &str) -> Result<DnValue, String> {
    if s.is_empty() {
        return Err(format!("failed to convert {}", s));
    }

    Ok(DnValue::Utf8String(s.to_string()))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Config { file } => {
            let config = Config::from_file(&file)
                .context("Error while obtaining the configurations from the file")?;

            let server_context = config
                .to_server_context()
                .context("Error while parsing the configuration file")?;

            let server = STSServer::build_from_context(server_context)
                .context("Error while creating the server")?;

            server
                .run()
                .context("Running the server resulted into an error")?;
        }
        Mode::Rekey {
            address,
            server_ip,
            organization_name,
            server_name,
            output,
        } => {
            let manager = RekeyClientManager::build(
                server_ip,
                organization_name,
                server_name,
                output,
                address,
            )
            .context("Failed to start the rekey manager")?;

            manager
                .rekey()
                .context("Failed to perform rekey operation")?;
        }
    }

    Ok(())
}
