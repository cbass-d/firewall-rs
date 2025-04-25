use anyhow::{Result, anyhow};
use clap::Parser;
use cli_log::*;
use firewall_rs::cli;
use pnet::datalink::{self};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{self};

#[derive(Parser, Serialize, Deserialize)]
struct Config {
    #[arg(short)]
    rules_file: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_cli_log!();
    debug!("Starting CLI");

    match cli::run().await {
        Ok(()) => {
            debug!("CLI exited");
        }
        Err(e) => {
            error!("Error running CLI: {e}");
            return Err(anyhow!("Error running app: {e}"));
        }
    };

    log_mem(Level::Info);

    Ok(())
}
