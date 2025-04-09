use super::rules::RuleSet;
use core::net::IpAddr;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

pub struct FirewallEngine {
    rules: RuleSet,
}

impl FirewallEngine {
    pub fn new(rules: RuleSet) -> Self {
        Self { rules }
    }

    pub fn process(&self, packet: &EthernetPacket) {
        match packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                self.handle_ipv4(packet);
            }
            EtherTypes::Ipv6 => {
                self.handle_ipv6(packet);
            }
            _ => {}
        }
    }

    pub fn display_rules(&self) {
        println!("{}", self.rules);
    }

    pub fn handle_ipv4(&self, packet: &EthernetPacket) {
        let ipv4_packet = Ipv4Packet::new(packet.payload()).unwrap();

        let source = IpAddr::from(ipv4_packet.get_source());
        let destination = IpAddr::from(ipv4_packet.get_destination());

        if self.rules.matches_allow(&source) {
            println!("allow source match for: {}", source);
        }
        if self.rules.matches_deny(&source) {
            println!("deny source match for: {}", source);
        }
        if self.rules.matches_log(&source) {
            println!("log source match for: {}", source);
        }

        if self.rules.matches_allow(&destination) {
            println!("allow destination match for: {}", destination);
        }
        if self.rules.matches_deny(&destination) {
            println!("deny destination match for: {}", destination);
        }
        if self.rules.matches_log(&destination) {
            println!("log destination match for: {}", destination);
        }
    }

    pub fn handle_ipv6(&self, packet: &EthernetPacket) {}

    pub fn handle_other(&self, packet: &EthernetPacket) {}
}
