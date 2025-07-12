use crate::app::{App, context::AppContext};
use anyhow::Result;
use cli_log::debug;
use tokio::{
    sync::broadcast::{self},
    task::JoinSet,
};

// Runs the main logic of the application
pub async fn run() -> Result<()> {
    let context = AppContext::new();
    let mut app = App::new().unwrap();

    let (shutdown_tx, _shutdown_rx) = broadcast::channel::<()>(1);

    let mut task_set = JoinSet::new();

    task_set.spawn(async move {
        let _ = app.run(context).await;
        shutdown_tx
            .send(())
            .expect("Unable to send shutdown signal");
    });

    while let Some(res) = task_set.join_next().await {
        debug!("task ended: {res:?}");
    }

    Ok(())
}
