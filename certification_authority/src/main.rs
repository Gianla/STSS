#![forbid(unsafe_code)]

pub mod config;
mod small_server;

use anyhow::{Context, Result};
use clap::Parser;
use config::Config;
use small_server::SmallServer;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "STSS Certification Authority")]
#[command(version = "0.1.0")]
#[command(about = "Minimal Certification Authority skeleton for STSS.")]
struct Cli {
    /// Path to the CA TOML configuration file.
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();

    info!(
        config_path = %cli.config.display(),
        "starting STSS Certification Authority"
    );

    let config = Config::from_file(cli.config)
        .context("failed to read the CA configuration file")?;

    let context = config
        .to_context()
        .context("failed to build the CA runtime context")?;

    SmallServer::build(context)
        .run()
        .await
        .context("Certification Authority stopped with an error")
}