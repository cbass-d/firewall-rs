use super::EventHandler;
use tokio::sync::mpsc::{self};

#[derive(Clone, Debug)]
pub enum Action {
    Quit,
    Return,
    SelectTableList,
    SelectPacketLog,
    AttachListener(String),
    DisplayHelp,
    EditRules,
}

pub struct UserInterface {
    pub action_tx: mpsc::UnboundedSender<Action>,
}

impl UserInterface {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<Action>, EventHandler) {
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let event_handler = EventHandler::new();

        (Self { action_tx }, action_rx, event_handler)
    }
}
