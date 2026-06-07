#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{ArgGroup, Parser};
use rcgen::DnValue;
use server::config::Config;
use server::rekey::RekeyClient;
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
        let address = cli.address.expect("missing CA address");
        let ca_name = cli.ca_name.expect("missing CA name");
        let server_ip = cli.server_ip.expect("missing server IP");
        let organization_name = cli.organization_name.expect("missing organization name");
        let server_name = cli.server_name.expect("missing server name");

        let output = PathBuf::from("new_server_tls_certificate.pem");

        let runtime = tokio::runtime::Runtime::new()
            .context("Error while creating Tokio runtime for rekey mode")?;

        runtime.block_on(async move {
            let client = RekeyClient::new(
                server_ip,
                organization_name,
                server_name,
                ca_name,
                output,
                address,
            )
            .await
            .context("Error while connecting to the Certification Authority")?;

            client
                .new_cert_sign_request()
                .await
                .context("Error while requesting a signed certificate from the CA")
        })?;
    }

    Ok(())
}
