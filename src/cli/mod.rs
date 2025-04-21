use crate::app::UserInterface;
use crate::app::app::App;
use crate::app::app_router::AppRouter;
use crate::app::components::{Component, ComponentRender};
use crate::app::controller::context::AppContext;
use crate::firewall::{self, engine::FirewallEngine, rules::RuleSet};
use anyhow::Result;
use clap::Parser;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};

#[derive(Parser, Serialize, Deserialize)]
struct Args {
    #[arg(short)]
    rules_file: String,
}

// Runs the main logic of the application
pub async fn run() -> Result<()> {
    let cli_args = Args::parse();

    let firewall_rules: RuleSet = confy::load_path(cli_args.rules_file)?;

    debug!("Using the following firewall rules {}", firewall_rules);

    //let mut engine = FirewallEngine::new(firewall_rules)?;

    let context = AppContext::new(firewall_rules);
    let mut app = App::new(context).unwrap();

    app.run().await;

    Ok(())
}
