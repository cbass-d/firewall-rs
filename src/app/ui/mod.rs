use super::EventHandler;
use crate::firewall::rules::FirewallAction;
use tokio::sync::mpsc::{self};

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Quit,
    Return,
    SelectRulesList,
    SelectPacketLog,
    DisplayHelp,
    EditRules(FirewallAction),
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
