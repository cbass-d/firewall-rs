use core::net::IpAddr;
use pnet::ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

#[derive(Deserialize, Debug, Clone, Copy)]
pub enum FirewallAction {
    Allow,
    Deny,
    Log,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Rule {
    pub sources: HashSet<IpAddr>,
    pub destinations: HashSet<IpAddr>,
    pub source_networks: HashSet<IpNetwork>,
    pub destination_networks: HashSet<IpNetwork>,
    pub dports: HashSet<u16>,
    pub sports: HashSet<u16>,
}

impl Rule {
    pub fn contains_addr(&self, address: &IpAddr) -> bool {
        self.sources.contains(address) || self.destinations.contains(address)
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "sources: {:?}\ndestinations: {:?}\nsource networks: {:?}\ndestination networks: {:?}\nsports: {:?}\ndports: {:?}",
            self.sources,
            self.destinations,
            self.source_networks,
            self.destination_networks,
            self.sports,
            self.dports
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct RuleSet {
    pub allow: Rule,
    pub deny: Rule,
    pub log: Rule,
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
            "allow\n{}\ndeny\n{}\nlog\n{}",
            self.allow, self.deny, self.log
        )
    }
}
