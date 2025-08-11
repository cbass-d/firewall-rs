use super::ActivePane;
use tokio::sync::broadcast::{self};

#[derive(Debug)]
pub struct AppContext {
    pub active_box: ActivePane,
    pub shutdown_channel: broadcast::Receiver<()>,
}

impl AppContext {
    pub fn new(shutdown_channel: broadcast::Receiver<()>) -> Self {
        Self {
            active_box: ActivePane::None,
            shutdown_channel,
        }
    }
}
