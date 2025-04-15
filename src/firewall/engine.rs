use super::interface::InterfaceStats;
use super::nft;
use super::rules::RuleSet;
use core::net::IpAddr;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

pub struct FirewallEngine {
    rules: RuleSet,
    interface_stats: InterfaceStats,
}

impl FirewallEngine {
    pub fn new(iface_name: String, rules: RuleSet) -> Self {
        match nft::create_new_table("bleh", rules.clone()) {
            Ok(()) => {
                println!("bleh");
            }
            Err(e) => {
                println!("{}", e);
            }
        }

        Self {
            rules,
            interface_stats: InterfaceStats::new(iface_name),
        }
    }

    pub fn process(&mut self, packet: &EthernetPacket) {
        self.interface_stats.add_total();
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

    pub fn display_stats(&self) {
        println!("{}", self.interface_stats);
    }

    pub fn handle_ipv4(&mut self, packet: &EthernetPacket) {
        let ipv4_packet = Ipv4Packet::new(packet.payload()).unwrap();

        let source = IpAddr::from(ipv4_packet.get_source());
        let destination = IpAddr::from(ipv4_packet.get_destination());

        if self.rules.matches_allow(&source) {
            println!("allow source match for: {}", source);
            self.interface_stats.add_allow();
        }
        if self.rules.matches_deny(&source) {
            println!("deny source match for: {}", source);
            self.interface_stats.add_deny();
        }
        if self.rules.matches_log(&source) {
            println!("log source match for: {}", source);
            self.interface_stats.add_log();
        }

        if self.rules.matches_allow(&destination) {
            println!("allow destination match for: {}", destination);
            self.interface_stats.add_allow();
        }
        if self.rules.matches_deny(&destination) {
            println!("deny destination match for: {}", destination);
            self.interface_stats.add_deny();
        }
        if self.rules.matches_log(&destination) {
            println!("log destination match for: {}", destination);
            self.interface_stats.add_log();
        }
    }

    pub fn handle_ipv6(&self, packet: &EthernetPacket) {}

    pub fn handle_other(&self, packet: &EthernetPacket) {}
}
