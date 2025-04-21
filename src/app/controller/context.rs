use crate::app::ActiveBox;
use crate::firewall::rules::RuleSet;

pub struct AppContext {
    pub ruleset: RuleSet,
    pub current_page: ActiveBox,
}

impl AppContext {
    pub fn new(ruleset: RuleSet) -> Self {
        Self {
            ruleset,
            current_page: ActiveBox::RulesList,
        }
    }
}
