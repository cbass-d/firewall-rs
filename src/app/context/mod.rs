use crate::firewall::{logging::LogEntry, rules::RuleSet};
use std::collections::VecDeque;

use super::ActiveBox;

#[derive(Debug)]
pub struct AppContext {
    pub ruleset: RuleSet,
    pub packet_log: VecDeque<LogEntry>,
    pub active_box: ActiveBox,
}

impl AppContext {
    pub fn new(ruleset: RuleSet) -> Self {
        Self {
            ruleset,
            packet_log: VecDeque::new(),
            active_box: ActiveBox::None,
        }
    }
}
