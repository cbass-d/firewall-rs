use anyhow::{Result, anyhow};
use clap::Parser;
use firewall::rules::RuleSet;
use log::{debug, error, info, log};
use pnet::datalink::{self};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{self};

use firewall::engine::FirewallEngine;

mod firewall;

#[derive(Parser, Serialize, Deserialize)]
struct Config {
    #[arg(short)]
    rules_file: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli_cfg = Config::parse();

    let firewall_rules: RuleSet = confy::load_path(cli_cfg.rules_file)?;

    debug!("Using following rules {}", firewall_rules);

    let mut engine = match FirewallEngine::new(firewall_rules) {
        Ok(engine) => engine,
        Err(e) => {
            return Err(e);
        }
    };

    engine.run().await;

    Ok(())
}
