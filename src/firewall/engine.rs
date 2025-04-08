use super::{packet, rules::RuleSet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
pub struct FirewallEngine {
    rules: RuleSet,
}

impl FirewallEngine {
    pub fn new(rules: RuleSet) -> Self {
        Self { rules }
    }

    pub fn process(&self, packet: &EthernetPacket) {
        match packet.get_ethertype() {
            EtherTypes::Ipv4 => {}
            EtherTypes::Ipv6 => {}
            _ => {}
        }
    }

    pub fn handle_ipv4(&self, packet: &EthernetPacket) {}

    pub fn handle_ipv6(&self, packet: &EthernetPacket) {}

    pub fn handle_other(&self, packet: &EthernetPacket) {}
}
