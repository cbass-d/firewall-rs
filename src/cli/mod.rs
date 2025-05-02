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

// Runs the main logic of the application
pub async fn run() -> Result<()> {
    let (mut engine, logs_rx) = FirewallEngine::new()?;

    let context = AppContext::new();
    let mut app = App::new(logs_rx.resubscribe()).unwrap();

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

    //let mut task_set = JoinSet::new();

    //// Spawn engine task in blocking thread pool
    //// allows for processing of packets while allowing
    //// the app task to run
    //task_set.spawn(async move {
    //    tokio::task::spawn_blocking(move || engine.run(shutdown_rx)).await;
    //});

    //task_set.spawn(async move {
    //    //app.run(context).await;
    //    shutdown_tx.send(());
    //});

    //while let Some(res) = task_set.join_next().await {
    //    debug!("{res:?}");
    //}

    Ok(())
}
