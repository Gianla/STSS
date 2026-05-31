#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{ArgGroup, Parser};
use rcgen::DnValue;
use server::config::Config;
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
    /// Starts the server with a configuration file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Starts the server in rekey mode.
    #[arg(long)]
    rekey: bool,

    #[arg(long, requires = "rekey")]
    address: Option<SocketAddr>,

    #[arg(long, requires = "rekey")]
    ca_name: Option<String>,

    #[arg(long, requires = "rekey")]
    server_ip: Option<IpAddr>,

    #[arg(long, value_parser = parse_dn_value, requires = "rekey")]
    organization_name: Option<DnValue>,

    #[arg(long, value_parser = parse_dn_value, requires = "rekey")]
    server_name: Option<DnValue>,
}

fn parse_dn_value(s: &str) -> Result<DnValue, String> {
    if s.is_empty() {
        return Err(format!("failed to convert {}", s));
    }

    Ok(DnValue::Utf8String(s.to_string()))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(toml_file) = cli.config {
        let config = Config::from_file(&toml_file)
            .context("Error while obtaining the configurations from the file")?;

        let server_context = config
            .to_server_context()
            .context("Error while parsing the configuration file")?;

        let server = STSServer::build_from_context(server_context)
            .context("Error while creating the server")?;

        server
            .run()
            .context("Running the server resulted into an error")?;
    } else if cli.rekey {
        unimplemented!()
        /*
        let address = cli.address.unwrap();
        let ca_name = cli.ca_name.unwrap();
        let server_ip = cli.server_ip.unwrap();
        let organization_name = cli.organization_name.unwrap();
        let server_name = cli.server_name.unwrap();
         */
    }

    Ok(())
}
