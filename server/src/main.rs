#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{ArgGroup, Parser};
use std::net::SocketAddr;
use std::path::PathBuf;

use server::config::Config;
use server::server::STSServer;

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
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Starts the server in order to renew its certificate by asking the specified CA.
    #[arg(short, long, value_name = "ADDRESS")]
    rekey: Option<SocketAddr>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(toml_file) = cli.config {
        let config = Config::from_file(toml_file)
            .context("Error while obtaining the configurations from the file")?;

        let server_context = config
            .to_server_context()
            .context("Error while parsing the configuration file")?;

        let server = STSServer::build_from_context(server_context)
            .context("Error while creating the server")?;

        server
            .run()
            .context("Running the server resulted into an error")
    } else if let Some(_ca_address) = cli.rekey {
        println!("This is to do!");
        Ok(())
    } else {
        println!("Invalid input, but this has to be done yet!");
        Ok(())
    }
}
