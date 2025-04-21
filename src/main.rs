use anyhow::{Result, anyhow};
use clap::Parser;
use firewall::rules::RuleSet;
use log::{debug, error, info, log};
use pnet::datalink::{self};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{self};

use firewall::engine::FirewallEngine;

mod app;
mod cli;
mod display;
mod firewall;

#[derive(Parser, Serialize, Deserialize)]
struct Config {
    #[arg(short)]
    rules_file: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    match cli::run().await {
        Ok(()) => {}
        Err(e) => {
            return Err(anyhow!("Error running app: {e}"));
        }
    };

    Ok(())
}
