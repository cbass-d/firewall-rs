use anyhow::{Result, anyhow};
use clap::Parser;
use log::{debug, error, info, log};
use pnet::datalink::{self};
use serde::{Deserialize, Serialize};

use firewall::engine::FirewallEngine;

mod firewall;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let firewall_rules: firewall::rules::RuleSet = confy::load("firewall-rs", "firewall-rules")?;

    debug!("Using following rules {}", firewall_rules);

    let local_data_dir = match dirs::data_local_dir() {
        Some(dir) => dir,
        None => {
            return Err(anyhow!("Unable to find local data directory"));
        }
    };

    let mut engine = match FirewallEngine::new(firewall_rules) {
        Ok(engine) => engine,
        Err(e) => {
            return Err(e);
        }
    };

    engine.run().await;

    Ok(())
}
