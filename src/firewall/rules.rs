use core::net::IpAddr;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Deserialize, Debug)]
pub enum Action {
    Allow,
    Deny,
    Log,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Rule {
    sources: Vec<String>,
    destinations: Vec<String>,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            sources: vec![],
            destinations: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RuleSet {
    allow: Rule,
    deny: Rule,
    log: Rule,
}

impl Default for RuleSet {
    fn default() -> Self {
        Self {
            allow: Rule::default(),
            deny: Rule::default(),
            log: Rule::default(),
        }
    }
}
