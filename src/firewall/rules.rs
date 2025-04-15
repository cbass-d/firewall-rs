use core::net::IpAddr;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::path::Path;

#[derive(Deserialize, Debug)]
pub enum Action {
    Allow,
    Deny,
    Log,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Rule {
    pub sources: HashSet<IpAddr>,
    pub destinations: HashSet<IpAddr>,
    pub ports: HashSet<u32>,
}

impl Rule {
    pub fn contains_addr(&self, address: &IpAddr) -> bool {
        self.sources.contains(address) || self.destinations.contains(address)
    }
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            sources: HashSet::new(),
            destinations: HashSet::new(),
            ports: HashSet::new(),
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "sources: {:?}\ndestinations: {:?}",
            self.sources, self.destinations
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RuleSet {
    pub allow: Rule,
    pub deny: Rule,
    pub log: Rule,
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

impl RuleSet {
    pub fn matches_allow(&self, address: &IpAddr) -> bool {
        self.allow.contains_addr(address)
    }
    pub fn matches_deny(&self, address: &IpAddr) -> bool {
        self.deny.contains_addr(address)
    }
    pub fn matches_log(&self, address: &IpAddr) -> bool {
        self.log.contains_addr(address)
    }
}

impl fmt::Display for RuleSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "allow:\n{}\ndeny:\n{}\nlog:\n{}",
            self.allow, self.deny, self.log
        )
    }
}
