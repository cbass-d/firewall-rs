use crate::{
    app::{App, context::AppContext},
    firewall::{engine::FirewallEngine, rules::RuleSet},
};
use anyhow::Result;
use clap::Parser;
use cli_log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::{
    sync::broadcast::{self},
    task::JoinSet,
};

#[derive(Parser, Serialize, Deserialize, Debug)]
struct Args {
    #[arg(short)]
    rules_file: String,
}

// Runs the main logic of the application
pub async fn run() -> Result<()> {
    let cli_args = Args::parse();
    debug!("Running with the following CLI args: {cli_args:?}");

    let firewall_rules: RuleSet = confy::load_path(cli_args.rules_file)?;

    debug!(
        "Using the following firewall rules {}",
        firewall_rules.clone()
    );

    let (mut engine, logs_rx) = FirewallEngine::new(firewall_rules.clone())?;

    let context = AppContext::new(firewall_rules);
    let mut app = App::new(logs_rx.resubscribe()).unwrap();

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

    let mut task_set = JoinSet::new();

    // Spawn engine task in blocking thread pool
    // allows for processing of packets while allowing
    // the app task to run
    task_set.spawn(async move {
        tokio::task::spawn_blocking(move || engine.run(shutdown_rx)).await;
    });

    task_set.spawn(async move {
        app.run(context).await;
        shutdown_tx.send(());
    });

    while let Some(res) = task_set.join_next().await {
        debug!("{res:?}");
    }

    Ok(())
}
